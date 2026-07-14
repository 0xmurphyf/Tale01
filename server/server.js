import express from 'express';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';

// ── Config ──
const CONFIG = {
  PORT: 3000,
  JWT_SECRET: process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex'),
  JWT_EXPIRES: '15m',
  EPUB_KEY: process.env.EPUB_KEY || 'SAI+lQJC/M2p70LliXMOK3AhHjfFBA3CryLHhEsDxEE=',
};

// ── Rate limiter (simple in-memory) ──
const rateLimitMap = new Map(); // IP -> { count, resetTime }
const RATE_LIMIT = { windowMs: 60_000, max: 10 }; // 10 req/min per IP

function rateLimit(req, res, next) {
  const ip = req.ip || req.socket.remoteAddress || 'unknown';
  const now = Date.now();
  let entry = rateLimitMap.get(ip);
  if (!entry || now > entry.resetTime) {
    entry = { count: 0, resetTime: now + RATE_LIMIT.windowMs };
    rateLimitMap.set(ip, entry);
  }
  entry.count++;
  if (entry.count > RATE_LIMIT.max) {
    return res.status(429).json({ error: 'Too many requests. Try again later.' });
  }
  next();
}

// Clean up rate limit map periodically
setInterval(() => {
  const now = Date.now();
  for (const [ip, entry] of rateLimitMap) {
    if (now > entry.resetTime) rateLimitMap.delete(ip);
  }
}, 60_000);

// ── Express ──
const app = express();
app.use(express.json());
app.set('trust proxy', 1);

// ── Health ──
app.get('/api/health', (_req, res) => {
  res.json({ status: 'ok' });
});

// ── POST /api/verify ──
// The client-side gate already verified: 1) wallet signature, 2) NFT ownership.
// Server issues a short-lived JWT as a session marker.
// Defense: 15-min expiry, rate limiting, unique token ID.
app.post('/api/verify', rateLimit, async (req, res) => {
  const { address } = req.body;

  if (!address) {
    return res.status(400).json({ error: 'Missing address' });
  }

  // Validate address format (must be valid Sui hex address)
  if (!/^0x[0-9a-fA-F]{64}$/.test(address)) {
    return res.status(400).json({ error: 'Invalid Sui address format' });
  }

  console.log(`[VERIFY] Gate passed for ${address} — issuing JWT + epub key`);
  const token = jwt.sign(
    {
      address,
      verifiedAt: Date.now(),
      jti: crypto.randomBytes(8).toString('hex'),
    },
    CONFIG.JWT_SECRET,
    { expiresIn: CONFIG.JWT_EXPIRES }
  );
  res.json({ token, epubKey: CONFIG.EPUB_KEY });
});

// ── Warn if JWT_SECRET is not set ──
if (!process.env.JWT_SECRET) {
  console.warn('[WARNING] JWT_SECRET not set. Using random secret (tokens invalid on restart).');
  console.warn('[WARNING] Set JWT_SECRET env var in Railway for persistent tokens.');
}

// ── Start ──
app.listen(CONFIG.PORT, () => {
  console.log(`[VOXX Gate Server] Running on port ${CONFIG.PORT}`);
});
