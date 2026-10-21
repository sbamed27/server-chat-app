import { defineConfig } from 'vitest/config';

export default defineConfig({
    test: {
        environment: 'node',
        include: ['test/**/*.test.js'],
        setupFiles: ['test/setup.js'],
        // bcrypt hashing at cost 10 is intentionally slow
        testTimeout: 15000,
        hookTimeout: 15000
    }
});
