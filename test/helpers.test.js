import { describe, it, expect } from 'vitest';
import jwt from 'jsonwebtoken';
import { getRoomName, verifySocketToken, JWT_SECRET } from '../server.js';

function verify(token) {
    return new Promise((resolve) => {
        verifySocketToken(token, (err, decoded) => resolve({ err, decoded }));
    });
}

describe('getRoomName', () => {
    it('produces the same room for both participants', () => {
        expect(getRoomName(2, 7)).toBe('dm_2_7');
        expect(getRoomName(7, 2)).toBe('dm_2_7');
    });

    it('sorts numerically, not lexicographically', () => {
        expect(getRoomName(10, 9)).toBe('dm_9_10');
    });

    it('coerces string ids to integers', () => {
        expect(getRoomName('12', '3')).toBe('dm_3_12');
    });
});

describe('verifySocketToken', () => {
    it('rejects a missing token', async () => {
        const { err, decoded } = await verify(undefined);

        expect(decoded).toBeUndefined();
        expect(err.message).toBe('Authentication error: Token missing');
    });

    it('rejects an invalid token', async () => {
        const { err, decoded } = await verify('not-a-real-token');

        expect(decoded).toBeUndefined();
        expect(err.message).toBe('Authentication error: Invalid token');
    });

    it('accepts a valid token and returns its claims', async () => {
        const token = jwt.sign({ id: 9, username: 'bob' }, JWT_SECRET, { expiresIn: '1h' });

        const { err, decoded } = await verify(token);

        expect(err).toBeNull();
        expect(decoded.id).toBe(9);
        expect(decoded.username).toBe('bob');
    });
});
