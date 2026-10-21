import { describe, it, expect, afterEach, vi } from 'vitest';
import request from 'supertest';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { app, pool, JWT_SECRET } from '../server.js';

function authHeader(payload = { id: 1, username: 'alice' }) {
    return `Bearer ${jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' })}`;
}

function spyOnQuery() {
    return vi.spyOn(pool, 'query');
}

afterEach(() => {
    vi.restoreAllMocks();
});

describe('GET /health', () => {
    it('reports ok without touching the database', async () => {
        const query = spyOnQuery();

        const res = await request(app).get('/health');

        expect(res.status).toBe(200);
        expect(res.body).toEqual({ status: 'ok' });
        expect(query).not.toHaveBeenCalled();
    });
});

describe('POST /api/signup', () => {
    it('rejects a missing username or password', async () => {
        const query = spyOnQuery();

        const res = await request(app).post('/api/signup').send({ username: 'alice' });

        expect(res.status).toBe(400);
        expect(res.body.error).toBe('Username and password are required');
        expect(query).not.toHaveBeenCalled();
    });

    it('creates a user, hashes the password and returns a usable token', async () => {
        const query = spyOnQuery().mockResolvedValueOnce({
            rows: [{ id: 7, username: 'alice' }]
        });

        const res = await request(app)
            .post('/api/signup')
            .send({ username: 'alice', password: 'secret123' });

        expect(res.status).toBe(200);
        expect(res.body.success).toBe(true);
        expect(res.body.username).toBe('alice');

        const decoded = jwt.verify(res.body.token, JWT_SECRET);
        expect(decoded.id).toBe(7);

        const params = query.mock.calls[0][1];
        expect(params[0]).toBe('alice');
        expect(params[1]).not.toBe('secret123');
        expect(params[1]).toMatch(/^\$2[aby]\$/);
    });

    it('returns 400 when the username is already taken', async () => {
        spyOnQuery().mockRejectedValueOnce(Object.assign(new Error('duplicate'), { code: '23505' }));

        const res = await request(app)
            .post('/api/signup')
            .send({ username: 'alice', password: 'secret123' });

        expect(res.status).toBe(400);
        expect(res.body.error).toBe('Username already taken');
    });
});

describe('POST /api/signin', () => {
    it('rejects a missing username or password', async () => {
        const query = spyOnQuery();

        const res = await request(app).post('/api/signin').send({});

        expect(res.status).toBe(400);
        expect(query).not.toHaveBeenCalled();
    });

    it('rejects an unknown user', async () => {
        spyOnQuery().mockResolvedValueOnce({ rows: [] });

        const res = await request(app)
            .post('/api/signin')
            .send({ username: 'nobody', password: 'secret123' });

        expect(res.status).toBe(400);
        expect(res.body.error).toBe('Invalid username or password');
    });

    it('rejects a wrong password', async () => {
        const password_hash = await bcrypt.hash('correct-password', 10);
        spyOnQuery().mockResolvedValueOnce({
            rows: [{ id: 1, username: 'alice', password_hash }]
        });

        const res = await request(app)
            .post('/api/signin')
            .send({ username: 'alice', password: 'wrong-password' });

        expect(res.status).toBe(400);
        expect(res.body.error).toBe('Invalid username or password');
    });

    it('returns a token for valid credentials', async () => {
        const password_hash = await bcrypt.hash('correct-password', 10);
        spyOnQuery().mockResolvedValueOnce({
            rows: [{ id: 1, username: 'alice', password_hash }]
        });

        const res = await request(app)
            .post('/api/signin')
            .send({ username: 'alice', password: 'correct-password' });

        expect(res.status).toBe(200);
        expect(res.body.success).toBe(true);
        expect(jwt.verify(res.body.token, JWT_SECRET).id).toBe(1);
    });
});

describe('GET /api/users/search', () => {
    it('rejects a request without a token', async () => {
        const res = await request(app).get('/api/users/search').query({ q: 'bob' });

        expect(res.status).toBe(401);
        expect(res.body.error).toBe('Token missing');
    });

    it('rejects a malformed token', async () => {
        const res = await request(app)
            .get('/api/users/search')
            .set('Authorization', 'Bearer not-a-real-token')
            .query({ q: 'bob' });

        expect(res.status).toBe(403);
        expect(res.body.error).toBe('Invalid token');
    });

    it('returns an empty list for a blank query without querying the database', async () => {
        const query = spyOnQuery();

        const res = await request(app)
            .get('/api/users/search')
            .set('Authorization', authHeader())
            .query({ q: '   ' });

        expect(res.status).toBe(200);
        expect(res.body).toEqual({ users: [] });
        expect(query).not.toHaveBeenCalled();
    });

    it('returns matching users for a query', async () => {
        const rows = [{ id: 2, username: 'bob', display_name: 'Bob', status_message: 'hi' }];
        const query = spyOnQuery().mockResolvedValueOnce({ rows });

        const res = await request(app)
            .get('/api/users/search')
            .set('Authorization', authHeader())
            .query({ q: 'bo' });

        expect(res.status).toBe(200);
        expect(res.body.users).toEqual(rows);
        expect(query.mock.calls[0][1]).toEqual([1, '%bo%']);
    });
});

describe('GET /api/profile/:identifier', () => {
    it('looks up a numeric identifier by id', async () => {
        const profile = { id: 42, username: 'alice', display_name: 'Alice' };
        const query = spyOnQuery().mockResolvedValueOnce({ rows: [profile] });

        const res = await request(app).get('/api/profile/42');

        expect(res.status).toBe(200);
        expect(res.body).toEqual({ success: true, profile });
        expect(query.mock.calls[0][0]).toContain('WHERE id = $1');
        expect(query.mock.calls[0][1]).toEqual(['42']);
    });

    it('looks up a non-numeric identifier by username', async () => {
        const query = spyOnQuery().mockResolvedValueOnce({ rows: [{ id: 5, username: 'alice' }] });

        const res = await request(app).get('/api/profile/alice');

        expect(res.status).toBe(200);
        expect(query.mock.calls[0][0]).toContain('WHERE username = $1');
        expect(query.mock.calls[0][1]).toEqual(['alice']);
    });

    it('returns 404 when the user does not exist', async () => {
        spyOnQuery().mockResolvedValueOnce({ rows: [] });

        const res = await request(app).get('/api/profile/ghost');

        expect(res.status).toBe(404);
        expect(res.body.error).toBe('User not found');
    });
});

describe('PUT /api/profile', () => {
    it('rejects a request without a token', async () => {
        const res = await request(app).put('/api/profile').send({ bio: 'hello' });

        expect(res.status).toBe(401);
        expect(res.body.error).toBe('Token missing');
    });

    it('trims and truncates profile fields', async () => {
        const query = spyOnQuery().mockResolvedValueOnce({
            rows: [{ id: 1, username: 'alice', display_name: 'A'.repeat(100) }]
        });

        const res = await request(app)
            .put('/api/profile')
            .set('Authorization', authHeader())
            .send({
                display_name: `  ${'A'.repeat(101)}  `,
                bio: `  ${'B'.repeat(501)}  `,
                status_message: `  ${'C'.repeat(256)}  `
            });

        expect(res.status).toBe(200);
        expect(res.body.success).toBe(true);

        const [sql, values] = query.mock.calls[0];
        expect(sql).toContain('display_name = $1');
        expect(sql).toContain('bio = $2');
        expect(sql).toContain('status_message = $3');
        expect(sql).toContain('WHERE id = $4');
        expect(values).toEqual([
            'A'.repeat(100),
            'B'.repeat(500),
            'C'.repeat(255),
            1
        ]);
    });

    it('returns the current profile when no fields are supplied', async () => {
        const current = { id: 1, username: 'alice', display_name: 'Alice' };
        const query = spyOnQuery().mockResolvedValueOnce({ rows: [current] });

        const res = await request(app)
            .put('/api/profile')
            .set('Authorization', authHeader())
            .send({});

        expect(res.status).toBe(200);
        expect(res.body).toEqual({ success: true, profile: current });
        expect(query).toHaveBeenCalledTimes(1);
        expect(query.mock.calls[0][0]).not.toContain('UPDATE users');
    });
});
