import express from 'express';
import jwt from 'jsonwebtoken';
import { SuiClient, getFullnodeUrl } from '@mysten/sui/client';
import { readFileSync, existsSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import crypto from 'crypto';

const __dirname = dirname(fileURLToPath(import.meta.url));

// ── Config ──
const CONFIG = {
  PORT: 3000,
  NFT_TYPE: '0xe649354aa848a8ae43d52a2bf75301b3d67dd6654c8df525650c5afe86518dc5::voxx_book_pass::Nft',
  NETWORK: process.env.SUI_NETWORK || 'mainnet',
  JWT_SECRET: process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex'),
  JWT_EXPIRES: '1h',
  EPUB_PATH: join(__dirname, '..', 'dark_transcendence.epub'),
  READER_PATH: join(__dirname, '..', 'reader.html'),
};

// ── Sui Client (JSON RPC - same as client-side gate) ──
const rpcUrl = process.env.SUI_RPC_URL || getFullnodeUrl(CONFIG.NETWORK);
const suiClient = new SuiClient({ url: rpcUrl });

// ── Express ──
const app = express();
app.use(express.json());

// ── JWT middleware ──
function authMiddleware(req, res, next) {
  let token = null;
  const authHeader = req.headers.authorization;
  if (authHeader?.startsWith('Bearer ')) {
    token = authHeader.slice(7);
  }
  if (!token) {
    token = req.query.token;
  }
  if (!token) {
    return res.status(401).json({ error: 'Missing or invalid token' });
  }
  try {
    req.user = jwt.verify(token, CONFIG.JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'Token expired or invalid' });
  }
}

// ── Health ──
app.get('/api/health', (_req, res) => {
  res.json({ status: 'ok' });
});

// ── POST /api/verify ──
// Uses the EXACT SAME API as the client-side gate:
//   getOwnedObjects() → checkKiosks() → issue JWT
app.post('/api/verify', async (req, res) => {
  const { address } = req.body;

  if (!address) {
    return res.status(400).json({ error: 'Missing address' });
  }

  try {
    // Step 1: Check direct wallet ownership (identical to gate's s0())
    console.log(`[VERIFY] Checking wallet-held NFT for ${address}...`);
    const ownedObjects = await suiClient.getOwnedObjects({
      owner: address,
      filter: { StructType: CONFIG.NFT_TYPE },
      limit: 1,
    });

    if (ownedObjects.data.length > 0) {
      console.log(`[VERIFY] NFT found directly in wallet: ${address}`);
      const token = issueToken(address);
      return res.json({ token });
    }

    // Step 2: Check inside Sui Kiosks (identical to gate's SS())
    console.log(`[VERIFY] Scanning kiosks for ${address}...`);
    const foundInKiosk = await checkKiosks(address);

    if (foundInKiosk) {
      console.log(`[VERIFY] NFT found in kiosk: ${address}`);
      const token = issueToken(address);
      return res.json({ token });
    }

    console.log(`[VERIFY] No NFT found for ${address}`);
    return res.status(403).json({ error: 'No VOXX Book Pass NFT found on this account' });
  } catch (err) {
    console.error('Verify error:', err);
    res.status(500).json({ error: 'Verification failed: ' + (err.message || 'Unknown error') });
  }
});

function issueToken(address) {
  return jwt.sign(
    { address, verifiedAt: Date.now() },
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

// ── Kiosk scanning (EXACT SAME LOGIC as gate's SS() function) ──
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

// ── Start ──
app.listen(CONFIG.PORT, () => {
  console.log(`[VOXX Gate Server] Running on port ${CONFIG.PORT}`);
  console.log(`[VOXX Gate Server] Network: ${CONFIG.NETWORK}`);
  console.log(`[VOXX Gate Server] RPC: ${rpcUrl}`);
  console.log(`[VOXX Gate Server] NFT: ${CONFIG.NFT_TYPE}`);
  console.log(`[VOXX Gate Server] EPUB: ${existsSync(CONFIG.EPUB_PATH) ? 'found' : 'MISSING!'}`);
});
