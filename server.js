import express from 'express';
import { createServer } from 'http';
import { Server } from 'socket.io';
import { createClient } from 'redis';
import { createAdapter } from '@socket.io/redis-adapter';
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
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS messages (
                id SERIAL PRIMARY KEY,
                sender_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                recipient_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                content TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);

        console.log('PostgreSQL: tables and columns verified/created with Auth support');
    } catch (err) {
        console.error('Database initialization error:', err);
    }
}
initDB();

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

    try {
        // Send back list of all registered users (except self) upon connection
        const { rows: users } = await pool.query('SELECT username FROM users WHERE id != $1', [socket.userId]);
        socket.emit('user_list', users.map(u => u.username));
    } catch (err) {
        console.error('Error fetching user list:', err);
    }

    // Join a private chat room using immutable IDs
    socket.on('join_private_chat', async ({ recipient }, callback) => {
        try {
            const recipientRes = await pool.query('SELECT id FROM users WHERE username = $1', [recipient]);
            if (recipientRes.rows.length === 0) return callback({ success: false });
            const recipientId = recipientRes.rows[0].id;

            const roomName = getRoomName(socket.userId, recipientId);
            socket.join(roomName);

            const { rows } = await pool.query(`
                SELECT u.username AS sender, m.content 
                FROM messages m 
                JOIN users u ON m.sender_id = u.id 
                WHERE (m.sender_id = $1 AND m.recipient_id = $2) 
                OR (m.sender_id = $2 AND m.recipient_id = $1)
                ORDER BY m.created_at ASC 
                LIMIT 50
            `, [socket.userId, recipientId]);

            callback({ success: true, history: rows });
        } catch (err) {
            console.error('Error joining private chat:', err);
            callback({ success: false });
        }
    });

    // Handle incoming private messages using IDs
    socket.on('private_message', async ({ recipient, content }) => {
        try {
            const recipientRes = await pool.query('SELECT id FROM users WHERE username = $1', [recipient]);
            if (recipientRes.rows.length === 0) return;
            const recipientId = recipientRes.rows[0].id;

            await pool.query(`
                INSERT INTO messages (sender_id, recipient_id, content) 
                VALUES ($1, $2, $3)
            `, [socket.userId, recipientId, content]);

            const roomName = getRoomName(socket.userId, recipientId);

            socket.to(roomName).emit('private_message', {
                sender: socket.username,
                content
            });
        } catch (err) {
            console.error('Error saving private message:', err);
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