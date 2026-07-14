import express from 'express';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { SuiClient, getFullnodeUrl } from '@mysten/sui/client';
import { readFileSync, existsSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));

// ── Config ──
const CONFIG = {
  PORT: 3000,
  NFT_TYPE: '0xe649354aa848a8ae43d52a2bf75301b3d67dd6654c8df525650c5afe86518dc5::voxx_book_pass::Nft',
  NETWORK: process.env.SUI_NETWORK || 'mainnet',
  JWT_SECRET: process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex'),
  JWT_EXPIRES: '15m',  // Short-lived tokens
  EPUB_PATH: join(__dirname, '..', 'dark_transcendence.epub'),
  READER_PATH: join(__dirname, '..', 'reader.html'),
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

// ── Sui Client ──
const rpcUrl = process.env.SUI_RPC_URL || getFullnodeUrl(CONFIG.NETWORK);
const suiClient = new SuiClient({ url: rpcUrl });

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
    // Verify IP binding (prevent token sharing across IPs)
    const currentIp = req.ip || req.socket.remoteAddress || '';
    if (decoded.ipHash && decoded.ipHash !== hashIp(currentIp)) {
      return res.status(401).json({ error: 'Token bound to different IP' });
    }
    req.user = decoded;
    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Token expired' });
    }
    return res.status(401).json({ error: 'Token invalid' });
  }
}

function hashIp(ip) {
  return crypto.createHash('sha256').update(ip).digest('hex').slice(0, 16);
}

// ── Health ──
app.get('/api/health', (_req, res) => {
  res.json({ status: 'ok' });
});

// ── POST /api/verify ──
// The client-side gate already verified the signature and NFT ownership.
// Server independently re-checks NFT ownership on-chain.
// NOTE: Full signature re-verification requires capturing the raw signature
// from the wallet, which is not feasible without modifying the gate bundle.
// Defense-in-depth: IP binding, rate limiting, short-lived tokens.
app.post('/api/verify', rateLimit, async (req, res) => {
  const { address } = req.body;

  if (!address) {
    return res.status(400).json({ error: 'Missing address' });
  }

  // Validate address format (must be valid Sui hex address)
  if (!/^0x[0-9a-fA-F]{64}$/.test(address)) {
    return res.status(400).json({ error: 'Invalid Sui address format' });
  }

  try {
    // Step 1: Check direct wallet ownership (same API as client gate)
    console.log(`[VERIFY] Checking wallet-held NFT for ${address}...`);
    const ownedObjects = await suiClient.getOwnedObjects({
      owner: address,
      filter: { StructType: CONFIG.NFT_TYPE },
      limit: 1,
    });

    if (ownedObjects.data.length > 0) {
      console.log(`[VERIFY] NFT found directly in wallet: ${address}`);
      const token = issueToken(address, req);
      return res.json({ token });
    }

    // Step 2: Check inside Sui Kiosks (same logic as client gate's SS())
    console.log(`[VERIFY] Scanning kiosks for ${address}...`);
    const foundInKiosk = await checkKiosks(address);

    if (foundInKiosk) {
      console.log(`[VERIFY] NFT found in kiosk: ${address}`);
      const token = issueToken(address, req);
      return res.json({ token });
    }

    console.log(`[VERIFY] No NFT found for ${address}`);
    return res.status(403).json({ error: 'No VOXX Book Pass NFT found on this account' });
  } catch (err) {
    console.error('Verify error:', err);
    res.status(500).json({ error: 'Verification failed: ' + (err.message || 'Unknown error') });
  }
});

function issueToken(address, req) {
  const ip = req.ip || req.socket.remoteAddress || '';
  return jwt.sign(
    {
      address,
      ipHash: hashIp(ip),
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

// ── GET /api/reader ──
app.get('/api/reader', authMiddleware, (req, res) => {
  if (!existsSync(CONFIG.READER_PATH)) {
    return res.status(404).json({ error: 'Reader not found' });
  }

  console.log(`[READER] Served to ${req.user.address} at ${new Date().toISOString()}`);

  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
  res.sendFile(CONFIG.READER_PATH);
});

// ── Kiosk scanning ──
async function checkKiosks(address) {
  try {
    let cursor = null;
    do {
      const result = await suiClient.getOwnedKiosks({
        address,
        pagination: { cursor, limit: 50 },
      });

      const kioskChecks = await Promise.all(
        result.kioskIds.map((id) =>
          suiClient.getKiosk({ id }).catch(() => null)
        )
      );

      for (const kiosk of kioskChecks) {
        if (!kiosk) continue;
        const normalizedTarget = normalizeType(CONFIG.NFT_TYPE);
        const hasNft = kiosk.items.some(
          (item) => normalizeType(item.type) === normalizedTarget
        );
        if (hasNft) return true;
      }

      cursor = result.nextCursor;
      if (!result.hasNextPage || !cursor) break;
    } while (true);

    return false;
  } catch (err) {
    console.error('Kiosk scan error:', err);
    return false;
  }
}

function normalizeType(type) {
  return type.replace(/^0x0+/, '0x').toLowerCase();
}

// ── Warn if JWT_SECRET is not set ──
if (!process.env.JWT_SECRET) {
  console.warn('[WARNING] JWT_SECRET not set. Using random secret (tokens invalid on restart).');
  console.warn('[WARNING] Set JWT_SECRET env var in Railway for persistent tokens.');
}

// ── Start ──
app.listen(CONFIG.PORT, () => {
  console.log(`[VOXX Gate Server] Running on port ${CONFIG.PORT}`);
  console.log(`[VOXX Gate Server] Network: ${CONFIG.NETWORK}`);
  console.log(`[VOXX Gate Server] RPC: ${rpcUrl}`);
  console.log(`[VOXX Gate Server] NFT: ${CONFIG.NFT_TYPE}`);
  console.log(`[VOXX Gate Server] EPUB: ${existsSync(CONFIG.EPUB_PATH) ? 'found' : 'MISSING!'}`);
});
