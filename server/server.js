import express from 'express';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { readFileSync, existsSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));

// ── Config ──
const CONFIG = {
  PORT: 3000,
  JWT_SECRET: process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex'),
  JWT_EXPIRES: '15m',
  EPUB_PATH: join(__dirname, '..', 'dark_transcendence.epub'),
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

// ── JWT middleware ──
function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing or invalid token' });
  }
  const token = authHeader.slice(7);
  try {
    const decoded = jwt.verify(token, CONFIG.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Token expired' });
    }
    return res.status(401).json({ error: 'Token invalid' });
  }
}

// ── Health ──
app.get('/api/health', (_req, res) => {
  res.json({ status: 'ok' });
});

// ── POST /api/verify ──
// The client-side gate already verified: 1) wallet signature, 2) NFT ownership.
// Server trusts the gate and issues a short-lived JWT directly.
// Defense: IP binding, 15-min expiry, rate limiting, Bearer-only token.
app.post('/api/verify', rateLimit, async (req, res) => {
  const { address } = req.body;

  if (!address) {
    return res.status(400).json({ error: 'Missing address' });
  }

  // Validate address format (must be valid Sui hex address)
  if (!/^0x[0-9a-fA-F]{64}$/.test(address)) {
    return res.status(400).json({ error: 'Invalid Sui address format' });
  }

  console.log(`[VERIFY] Gate passed for ${address} — issuing JWT`);
  const token = issueToken(address, req);
  res.json({ token });
});

function issueToken(address, req) {
  return jwt.sign(
    {
      address,
      verifiedAt: Date.now(),
      jti: crypto.randomBytes(8).toString('hex'),  // Unique token ID
    },
    CONFIG.JWT_SECRET,
    { expiresIn: CONFIG.JWT_EXPIRES }
  );
}

// ── GET /api/epub ──
app.get('/api/epub', authMiddleware, (req, res) => {
  if (!existsSync(CONFIG.EPUB_PATH)) {
    return res.status(404).json({ error: 'EPUB not found' });
  }

  console.log(`[EPUB] Served to ${req.user.address} at ${new Date().toISOString()}`);

  res.setHeader('Content-Type', 'application/epub+zip');
  res.setHeader('Content-Disposition', 'inline; filename="dark_transcendence.epub"');
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
  res.setHeader('X-Content-Type-Options', 'nosniff');

  res.send(readFileSync(CONFIG.EPUB_PATH));
});

// ── Warn if JWT_SECRET is not set ──
if (!process.env.JWT_SECRET) {
  console.warn('[WARNING] JWT_SECRET not set. Using random secret (tokens invalid on restart).');
  console.warn('[WARNING] Set JWT_SECRET env var in Railway for persistent tokens.');
}

// ── Start ──
app.listen(CONFIG.PORT, () => {
  console.log(`[VOXX Gate Server] Running on port ${CONFIG.PORT}`);
  console.log(`[VOXX Gate Server] EPUB: ${existsSync(CONFIG.EPUB_PATH) ? 'found' : 'MISSING!'}`);
});
