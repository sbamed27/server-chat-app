// Must run before server.js is imported: the app only skips Redis/Postgres
// connections and httpServer.listen() when NODE_ENV is "test".
process.env.NODE_ENV = 'test';

// Keep tests hermetic. These are provided by EasyPanel in production, but the
// suite must pass on a machine (and CI runner) with no environment at all.
delete process.env.DATABASE_URL;
delete process.env.REDIS_URL;
