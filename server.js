import express from 'express';
import { createServer } from 'http';
import { Server } from 'socket.io';
import { createClient } from 'redis';
import { createAdapter } from '@socket.io/redis-adapter';
import cors from 'cors';
import pkg from 'pg';
const { Pool } = pkg;
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import os from 'os';

const app = express();
const httpServer = createServer(app);

// Essential: Parse JSON bodies for POST requests (/api/signup, /api/signin)
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || 'portfolio_super_secret_jwt_key_2026';

// CORS configuration
const allowedOrigins = process.env.ALLOWED_ORIGINS
    ? process.env.ALLOWED_ORIGINS.split(',')
    : ['http://localhost:3000'];

app.use(cors({
    origin: allowedOrigins,
    methods: ["GET", "POST"],
    credentials: true
}));

const io = new Server(httpServer, {
    cors: {
        origin: allowedOrigins,
        methods: ["GET", "POST"]
    },
    transports: ["websocket"]
});

// PostgreSQL Pool Connection
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
});

// Initialize Database Table with Password Security Support
async function initDB() {
    try {
        await pool.query(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                display_name VARCHAR(100),
                bio TEXT,
                status_message VARCHAR(255),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            ALTER TABLE users ADD COLUMN IF NOT EXISTS display_name VARCHAR(100);
            ALTER TABLE users ADD COLUMN IF NOT EXISTS bio TEXT;
            ALTER TABLE users ADD COLUMN IF NOT EXISTS status_message VARCHAR(255);

            CREATE TABLE IF NOT EXISTS messages (
                id SERIAL PRIMARY KEY,
                sender_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                recipient_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                content TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS friendships (
                id SERIAL PRIMARY KEY,
                sender_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                receiver_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                status VARCHAR(20) NOT NULL DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE (sender_id, receiver_id)
            );
        `);

        console.log('PostgreSQL: tables and columns verified/created with Auth, Profile & Friendship support');
    } catch (err) {
        console.error('Database initialization error:', err);
    }
}
initDB();

// Fetch accepted friends for a user with real-time presence from Redis (optimized with SMISMEMBER)
async function getAcceptedFriends(userId) {
    const { rows: friends } = await pool.query(`
        SELECT u.id, u.username, u.display_name, u.bio, u.status_message
        FROM users u
        JOIN friendships f ON (
            (f.sender_id = $1 AND f.receiver_id = u.id) OR 
            (f.receiver_id = $1 AND f.sender_id = u.id)
        )
        WHERE f.status = 'accepted'
        ORDER BY u.username ASC
    `, [userId]);

    if (friends.length === 0) {
        return [];
    }

    // High-scale optimization: check friend IDs directly via Redis SMISMEMBER (or pipeline fallback)
    // Avoids pulling the entire global online set into Node.js memory
    const friendIds = friends.map(f => f.id.toString());
    let presenceFlags = [];
    try {
        presenceFlags = await pubClient.smIsMember('online_users', friendIds);
    } catch (err) {
        const pipeline = pubClient.multi();
        friendIds.forEach(id => pipeline.sIsMember('online_users', id));
        presenceFlags = await pipeline.exec();
    }

    return friends.map((u, index) => ({
        id: u.id,
        username: u.username,
        displayName: u.display_name || u.username,
        bio: u.bio || '',
        statusMessage: u.status_message || '',
        isOnline: Boolean(presenceFlags && presenceFlags[index])
    }));
}

// Fetch incoming pending requests for a user
async function getPendingRequests(userId) {
    const { rows } = await pool.query(`
        SELECT f.id AS request_id, u.id AS sender_id, u.username AS sender_username, f.created_at
        FROM friendships f
        JOIN users u ON f.sender_id = u.id
        WHERE f.receiver_id = $1 AND f.status = 'pending'
        ORDER BY f.created_at DESC
    `, [userId]);
    return rows;
}

// Redis Setup
const redisUrl = process.env.REDIS_URL;
if (!redisUrl) throw new Error("FATAL: REDIS_URL environment variable is missing.");

const pubClient = createClient({ url: redisUrl });
const subClient = pubClient.duplicate();

pubClient.on('error', (err) => console.error('Redis Pub Error:', err));
subClient.on('error', (err) => console.error('Redis Sub Error:', err));

Promise.all([pubClient.connect(), subClient.connect()]).then(() => {
    io.adapter(createAdapter(pubClient, subClient));
    console.log('Redis Pub/Sub adapter connected');
});

// --- REST API: SIGN UP ---
app.post('/api/signup', async (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password are required' });
        }

        const salt = await bcrypt.genSalt(10);
        const passwordHash = await bcrypt.hash(password, salt);

        const result = await pool.query(
            'INSERT INTO users (username, password_hash) VALUES ($1, $2) RETURNING id, username',
            [username, passwordHash]
        );

        const user = result.rows[0];
        const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '7d' });

        res.json({ success: true, token, username: user.username });
    } catch (err) {
        if (err.code === '23505') {
            return res.status(400).json({ error: 'Username already taken' });
        }
        console.error('Signup error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// --- REST API: SIGN IN ---
app.post('/api/signin', async (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password are required' });
        }

        const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
        if (result.rows.length === 0) {
            return res.status(400).json({ error: 'Invalid username or password' });
        }

        const user = result.rows[0];
        const isMatch = await bcrypt.compare(password, user.password_hash);
        if (!isMatch) {
            return res.status(400).json({ error: 'Invalid username or password' });
        }

        const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '7d' });

        res.json({ success: true, token, username: user.username });
    } catch (err) {
        console.error('Signin error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// --- REST API: AUTHENTICATION MIDDLEWARE ---
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Token missing' });
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid token' });
        req.user = user;
        next();
    });
}

// --- REST API: USER SEARCH (Excludes self & existing relationships using NOT EXISTS for scale) ---
app.get('/api/users/search', authenticateToken, async (req, res) => {
    try {
        const query = req.query.q || '';
        if (!query.trim()) return res.json({ users: [] });
        const { rows } = await pool.query(`
            SELECT u.id, u.username, u.display_name, u.status_message FROM users u
            WHERE u.id != $1
              AND u.username ILIKE $2
              AND NOT EXISTS (
                  SELECT 1 FROM friendships f
                  WHERE ((f.sender_id = $1 AND f.receiver_id = u.id) OR (f.receiver_id = $1 AND f.sender_id = u.id))
                    AND f.status IN ('pending', 'accepted')
              )
            LIMIT 15
        `, [req.user.id, `%${query.trim()}%`]);
        res.json({ users: rows });
    } catch (err) {
        console.error('REST Search error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// --- REST API: GET USER PROFILE ---
app.get('/api/profile/:identifier', async (req, res) => {
    try {
        const { identifier } = req.params;
        const isNumeric = /^\d+$/.test(identifier);
        const query = isNumeric
            ? 'SELECT id, username, display_name, bio, status_message, created_at FROM users WHERE id = $1'
            : 'SELECT id, username, display_name, bio, status_message, created_at FROM users WHERE username = $1';
        const { rows } = await pool.query(query, [identifier]);
        if (rows.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }
        res.json({ success: true, profile: rows[0] });
    } catch (err) {
        console.error('Error fetching profile:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// --- REST API: UPDATE PROFILE (Protected by authenticateToken) ---
app.put('/api/profile', authenticateToken, async (req, res) => {
    try {
        const updates = [];
        const values = [];
        let paramIdx = 1;
        const { display_name, bio, status_message } = req.body;

        if (display_name !== undefined) {
            updates.push(`display_name = $${paramIdx++}`);
            values.push(display_name ? display_name.trim().substring(0, 100) : null);
        }
        if (bio !== undefined) {
            updates.push(`bio = $${paramIdx++}`);
            values.push(bio ? bio.trim().substring(0, 500) : null);
        }
        if (status_message !== undefined) {
            updates.push(`status_message = $${paramIdx++}`);
            values.push(status_message ? status_message.trim().substring(0, 255) : null);
        }

        if (updates.length === 0) {
            const { rows: currentRows } = await pool.query('SELECT id, username, display_name, bio, status_message, created_at FROM users WHERE id = $1', [req.user.id]);
            if (currentRows.length === 0) return res.status(404).json({ error: 'User not found' });
            return res.json({ success: true, profile: currentRows[0] });
        }

        values.push(req.user.id);
        const { rows } = await pool.query(`
            UPDATE users 
            SET ${updates.join(', ')}
            WHERE id = $${paramIdx}
            RETURNING id, username, display_name, bio, status_message, created_at
        `, values);

        if (rows.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        const updatedProfile = rows[0];

        // Broadcast profile update across redis / connected sockets
        io.emit('profile_updated', {
            id: updatedProfile.id,
            username: updatedProfile.username,
            displayName: updatedProfile.display_name || updatedProfile.username,
            bio: updatedProfile.bio || '',
            statusMessage: updatedProfile.status_message || ''
        });

        res.json({ success: true, profile: updatedProfile });
    } catch (err) {
        console.error('Error updating profile:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// --- REST API: PENDING FRIEND REQUESTS ---
app.get('/api/friends/requests', authenticateToken, async (req, res) => {
    try {
        const requests = await getPendingRequests(req.user.id);
        res.json({ requests });
    } catch (err) {
        console.error('REST Requests error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// --- SOCKET.IO AUTHENTICATION MIDDLEWARE ---
// Intercepts socket handshake, verifies JWT token before allowing connection
io.use((socket, next) => {
    const token = socket.handshake.auth.token;
    if (!token) {
        return next(new Error('Authentication error: Token missing'));
    }

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) {
            return next(new Error('Authentication error: Invalid token'));
        }
        socket.userId = decoded.id;
        socket.username = decoded.username;
        next();
    });
});

// Helper to create a consistent, unique room name using immutable User IDs
function getRoomName(id1, id2) {
    const sortedIds = [parseInt(id1), parseInt(id2)].sort((a, b) => a - b);
    return `dm_${sortedIds[0]}_${sortedIds[1]}`;
}

io.on('connection', async (socket) => {
    console.log(`[Replica Host: ${os.hostname()}] Authenticated user connected: ${socket.username} (ID: ${socket.userId})`);

    // Join personal user room so multi-replica nodes can target this user directly
    socket.join(`user_${socket.userId}`);

    try {
        // 1. Add user ID to Redis online set
        await pubClient.sAdd('online_users', socket.userId.toString());

        // Broadcast to all other connected clients that this user is now online
        socket.broadcast.emit('user_status', { id: socket.userId, username: socket.username, isOnline: true });

        // 2. Fetch ONLY users who share an 'accepted' friendship status with current user
        const friendsWithStatus = await getAcceptedFriends(socket.userId);
        socket.emit('user_list', friendsWithStatus);

        // 3. Fetch incoming pending requests for this user
        const pendingRequests = await getPendingRequests(socket.userId);
        socket.emit('friend_requests', pendingRequests);
    } catch (err) {
        console.error('Error fetching friends list or presence:', err);
    }

    // Handle user disconnect presence clean-up
    socket.on('disconnect', async () => {
        try {
            await pubClient.sRem('online_users', socket.userId.toString());
            socket.broadcast.emit('user_status', { id: socket.userId, username: socket.username, isOnline: false });
            console.log(`[Replica Host: ${os.hostname()}] User disconnected: ${socket.username}`);
        } catch (err) {
            console.error('Error handling disconnect presence:', err);
        }
    });

    // --- FRIEND SYSTEM: USER SEARCH (NOT EXISTS anti-pattern optimization) ---
    socket.on('search_users', async ({ query }, callback) => {
        try {
            if (!query || !query.trim()) {
                if (callback) return callback({ success: true, users: [] });
                return socket.emit('search_results', []);
            }
            const q = query.trim();
            const { rows } = await pool.query(`
                SELECT u.id, u.username, u.display_name, u.status_message FROM users u
                WHERE u.id != $1
                  AND u.username ILIKE $2
                  AND NOT EXISTS (
                      SELECT 1 FROM friendships f
                      WHERE ((f.sender_id = $1 AND f.receiver_id = u.id) OR (f.receiver_id = $1 AND f.sender_id = u.id))
                        AND f.status IN ('pending', 'accepted')
                  )
                LIMIT 15
            `, [socket.userId, `%${q}%`]);

            if (callback) callback({ success: true, users: rows });
            else socket.emit('search_results', rows);
        } catch (err) {
            console.error('Error searching users:', err);
            if (callback) callback({ success: false, error: 'Search failed' });
        }
    });

    // --- FRIEND SYSTEM: SEND FRIEND REQUEST ---
    socket.on('send_friend_request', async ({ targetUsername, targetUserId }, callback) => {
        try {
            let recipientId = targetUserId;
            if (!recipientId && targetUsername) {
                const res = await pool.query('SELECT id FROM users WHERE username = $1', [targetUsername]);
                if (res.rows.length > 0) recipientId = res.rows[0].id;
            }
            if (!recipientId) return callback && callback({ success: false, error: 'User not found' });
            if (recipientId === socket.userId) return callback && callback({ success: false, error: 'Cannot add yourself' });

            // Check if relationship already exists
            const existing = await pool.query(`
                SELECT id, sender_id, receiver_id, status FROM friendships
                WHERE (sender_id = $1 AND receiver_id = $2) OR (sender_id = $2 AND receiver_id = $1)
            `, [socket.userId, recipientId]);

            if (existing.rows.length > 0) {
                const rel = existing.rows[0];
                if (rel.status === 'accepted') {
                    return callback && callback({ success: false, error: 'Already friends' });
                }
                if (rel.status === 'pending') {
                    if (rel.sender_id === socket.userId) {
                        return callback && callback({ success: false, error: 'Friend request already pending' });
                    } else {
                        // The other user already sent a request, auto-accept
                        await pool.query("UPDATE friendships SET status = 'accepted', updated_at = NOW() WHERE id = $1", [rel.id]);

                        const myFriends = await getAcceptedFriends(socket.userId);
                        socket.emit('user_list', myFriends);
                        const myRequests = await getPendingRequests(socket.userId);
                        socket.emit('friend_requests', myRequests);

                        const targetFriends = await getAcceptedFriends(recipientId);
                        io.to(`user_${recipientId}`).emit('user_list', targetFriends);
                        const targetRequests = await getPendingRequests(recipientId);
                        io.to(`user_${recipientId}`).emit('friend_requests', targetRequests);
                        io.to(`user_${recipientId}`).emit('friend_request_accepted', {
                            friend_id: socket.userId,
                            friend_username: socket.username
                        });

                        return callback && callback({ success: true, accepted: true });
                    }
                }
                // If previously rejected, allow re-requesting
                await pool.query(`
                    UPDATE friendships SET sender_id = $1, receiver_id = $2, status = 'pending', updated_at = NOW()
                    WHERE id = $3
                `, [socket.userId, recipientId, rel.id]);
            } else {
                await pool.query(`
                    INSERT INTO friendships (sender_id, receiver_id, status)
                    VALUES ($1, $2, 'pending')
                `, [socket.userId, recipientId]);
            }

            // Real-time notification across Redis cluster to target user
            const receiverRequests = await getPendingRequests(recipientId);
            io.to(`user_${recipientId}`).emit('friend_requests', receiverRequests);
            io.to(`user_${recipientId}`).emit('new_friend_request', {
                sender_id: socket.userId,
                sender_username: socket.username
            });

            if (callback) callback({ success: true });
        } catch (err) {
            console.error('Error sending friend request:', err);
            if (callback) callback({ success: false, error: 'Failed to send request' });
        }
    });

    // --- FRIEND SYSTEM: ACCEPT FRIEND REQUEST ---
    socket.on('accept_friend_request', async ({ requestId }, callback) => {
        try {
            const check = await pool.query(
                "SELECT sender_id, receiver_id FROM friendships WHERE id = $1 AND receiver_id = $2 AND status = 'pending'",
                [requestId, socket.userId]
            );
            if (check.rows.length === 0) {
                return callback && callback({ success: false, error: 'Request not found' });
            }
            const { sender_id: senderId } = check.rows[0];

            await pool.query(
                "UPDATE friendships SET status = 'accepted', updated_at = NOW() WHERE id = $1",
                [requestId]
            );

            // Refresh current user's requests and accepted friends
            const myRequests = await getPendingRequests(socket.userId);
            socket.emit('friend_requests', myRequests);
            const myFriends = await getAcceptedFriends(socket.userId);
            socket.emit('user_list', myFriends);

            // Refresh and notify sender via their user room
            const senderFriends = await getAcceptedFriends(senderId);
            io.to(`user_${senderId}`).emit('user_list', senderFriends);
            io.to(`user_${senderId}`).emit('friend_request_accepted', {
                friend_id: socket.userId,
                friend_username: socket.username
            });

            if (callback) callback({ success: true });
        } catch (err) {
            console.error('Error accepting friend request:', err);
            if (callback) callback({ success: false, error: 'Failed to accept request' });
        }
    });

    // --- FRIEND SYSTEM: REJECT FRIEND REQUEST ---
    socket.on('reject_friend_request', async ({ requestId }, callback) => {
        try {
            await pool.query(
                "DELETE FROM friendships WHERE id = $1 AND receiver_id = $2",
                [requestId, socket.userId]
            );

            const myRequests = await getPendingRequests(socket.userId);
            socket.emit('friend_requests', myRequests);

            if (callback) callback({ success: true });
        } catch (err) {
            console.error('Error rejecting friend request:', err);
            if (callback) callback({ success: false, error: 'Failed to reject request' });
        }
    });

    // --- FRIEND SYSTEM: FETCH PENDING REQUESTS ---
    socket.on('get_friend_requests', async (callback) => {
        try {
            const requests = await getPendingRequests(socket.userId);
            if (callback) callback({ success: true, requests });
            else socket.emit('friend_requests', requests);
        } catch (err) {
            console.error('Error getting friend requests:', err);
        }
    });

    // Join a private chat room using immutable IDs
    socket.on('join_private_chat', async ({ recipient, recipientId }, callback) => {
        try {
            let targetId = recipientId;
            if (!targetId && recipient) {
                const recipientRes = await pool.query('SELECT id FROM users WHERE username = $1', [recipient]);
                if (recipientRes.rows.length === 0) return callback({ success: false });
                targetId = recipientRes.rows[0].id;
            }
            if (!targetId) return callback({ success: false });

            const roomName = getRoomName(socket.userId, targetId);
            socket.join(roomName);

            const { rows } = await pool.query(`
                SELECT u.username AS sender, m.content 
                FROM messages m 
                JOIN users u ON m.sender_id = u.id 
                WHERE (m.sender_id = $1 AND m.recipient_id = $2) 
                OR (m.sender_id = $2 AND m.recipient_id = $1)
                ORDER BY m.created_at ASC 
                LIMIT 50
            `, [socket.userId, targetId]);

            callback({ success: true, history: rows, recipientId: targetId });
        } catch (err) {
            console.error('Error joining private chat:', err);
            callback({ success: false });
        }
    });

    // Handle incoming private messages using IDs
    socket.on('private_message', async ({ recipient, recipientId, content }) => {
        try {
            let targetId = recipientId;
            if (!targetId && recipient) {
                const recipientRes = await pool.query('SELECT id FROM users WHERE username = $1', [recipient]);
                if (recipientRes.rows.length === 0) return;
                targetId = recipientRes.rows[0].id;
            }
            if (!targetId) return;

            await pool.query(`
                INSERT INTO messages (sender_id, recipient_id, content) 
                VALUES ($1, $2, $3)
            `, [socket.userId, targetId, content]);

            const roomName = getRoomName(socket.userId, targetId);

            socket.to(roomName).emit('private_message', {
                sender: socket.username,
                senderId: socket.userId,
                content
            });
        } catch (err) {
            console.error('Error saving private message:', err);
        }
    });

    // Handle typing indicator start
    socket.on('typing_start', async ({ recipientId, recipient }) => {
        try {
            let targetId = recipientId;
            if (!targetId && recipient) {
                const recipientRes = await pool.query('SELECT id FROM users WHERE username = $1', [recipient]);
                if (recipientRes.rows.length > 0) targetId = recipientRes.rows[0].id;
            }
            if (!targetId) return;

            const roomName = getRoomName(socket.userId, targetId);
            socket.to(roomName).emit('typing_start', {
                sender: socket.username,
                senderId: socket.userId
            });
        } catch (err) {
            console.error('Error handling typing_start:', err);
        }
    });

    // Handle typing indicator stop
    socket.on('typing_stop', async ({ recipientId, recipient }) => {
        try {
            let targetId = recipientId;
            if (!targetId && recipient) {
                const recipientRes = await pool.query('SELECT id FROM users WHERE username = $1', [recipient]);
                if (recipientRes.rows.length > 0) targetId = recipientRes.rows[0].id;
            }
            if (!targetId) return;

            const roomName = getRoomName(socket.userId, targetId);
            socket.to(roomName).emit('typing_stop', {
                sender: socket.username,
                senderId: socket.userId
            });
        } catch (err) {
            console.error('Error handling typing_stop:', err);
        }
    });
});

const PORT = process.env.PORT || 3000;
const server = httpServer.listen(PORT, () => console.log(`Server running on port ${PORT}`));

process.on('SIGTERM', () => {
    server.close(async () => {
        await pool.end();
        await Promise.all([pubClient.quit(), subClient.quit()]);
        process.exit(0);
    });
});