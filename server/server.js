import express from 'express';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { SuiClient, getFullnodeUrl } from '@mysten/sui/client';
import { verifyPersonalMessageSignature } from '@mysten/sui/verify';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ADDRESS_RE = /^0x[0-9a-fA-F]{64}$/;
const DEFAULT_NFT_TYPE = '0xe649354aa848a8ae43d52a2bf75301b3d67dd6654c8df525650c5afe86518dc5::voxx_book_pass::Nft';
const CHALLENGE_TTL_MS = 5 * 60_000;
const SESSION_SECONDS = 15 * 60;

function requiredConfig(env = process.env) {
  const jwtSecret = env.JWT_SECRET;
  const epubKey = env.EPUB_KEY;
  if (!jwtSecret || jwtSecret.length < 32) throw new Error('JWT_SECRET must be set to at least 32 characters');
  if (!epubKey || Buffer.from(epubKey, 'base64').length !== 32) throw new Error('EPUB_KEY must be a base64-encoded 32-byte key');
  return {
    port: Number(env.NODE_PORT || 3000),
    jwtSecret,
    epubKey,
    nftType: env.NFT_TYPE || DEFAULT_NFT_TYPE,
    rpcUrl: env.SUI_RPC_URL || getFullnodeUrl('mainnet'),
    readerPath: env.READER_PATH || path.resolve(__dirname, 'private', 'reader.html'),
    secureCookies: env.NODE_ENV === 'production',
  };
}

function normalizeType(type = '') {
  const parts = String(type).split('::');
  if (parts.length < 3) return String(type).toLowerCase();
  try { parts[0] = `0x${BigInt(parts[0]).toString(16)}`; } catch { /* preserve invalid value */ }
  return parts.join('::').toLowerCase();
}

function cookie(req, name) {
  const raw = req.headers.cookie || '';
  for (const part of raw.split(';')) {
    const [key, ...value] = part.trim().split('=');
    if (key === name) return decodeURIComponent(value.join('='));
  }
  return null;
}

function findKioskId(object) {
  const type = normalizeType(object?.data?.type);
  const fields = object?.data?.content?.fields;
  if (!fields) return null;
  if (type === normalizeType('0x2::kiosk::KioskOwnerCap')) return fields.for || null;
  if (type.endsWith('::personal_kiosk::personalkioskcap')) {
    return fields.cap?.fields?.for || fields.cap?.for || null;
  }
  return null;
}

async function addressOwnsNft(client, address, nftType) {
  const wanted = normalizeType(nftType);
  const kioskIds = [];
  let cursor = null;
  do {
    const page = await client.getOwnedObjects({
      owner: address,
      cursor,
      limit: 50,
      options: { showType: true, showContent: true },
    });
    for (const object of page.data) {
      if (normalizeType(object?.data?.type) === wanted) return true;
      const kioskId = findKioskId(object);
      if (kioskId) kioskIds.push(kioskId);
    }
    cursor = page.hasNextPage ? page.nextCursor : null;
  } while (cursor);

  for (const parentId of kioskIds) {
    let fieldCursor = null;
    do {
      const page = await client.getDynamicFields({ parentId, cursor: fieldCursor, limit: 50 });
      if (page.data.some((field) => normalizeType(field.objectType) === wanted)) return true;
      fieldCursor = page.hasNextPage ? page.nextCursor : null;
    } while (fieldCursor);
  }
  return false;
}

export function createApp(config, dependencies = {}) {
  const app = express();
  const challenges = new Map();
  const usedSignatures = new Map();
  const client = dependencies.client || new SuiClient({ url: config.rpcUrl });
  const verifySignature = dependencies.verifySignature || verifyPersonalMessageSignature;
  const ownsNft = dependencies.ownsNft || ((address) => addressOwnsNft(client, address, config.nftType));

  app.disable('x-powered-by');
  app.set('trust proxy', 1);
  app.use(express.json({ limit: '16kb' }));

  const rateLimitMap = new Map();
  function rateLimit(req, res, next) {
    const key = req.ip || req.socket.remoteAddress || 'unknown';
    const now = Date.now();
    const entry = rateLimitMap.get(key);
    if (!entry || now > entry.resetAt) rateLimitMap.set(key, { count: 1, resetAt: now + 60_000 });
    else if (++entry.count > 10) return res.status(429).json({ error: 'Too many requests' });
    next();
  }

  function requireSession(req, res, next) {
    try {
      const token = cookie(req, 'voxx_session');
      if (!token) throw new Error('missing');
      req.session = jwt.verify(token, config.jwtSecret, { algorithms: ['HS256'] });
      next();
    } catch {
      res.status(401).set('Cache-Control', 'no-store').json({ error: 'Authentication required' });
    }
  }

  app.get('/api/health', (_req, res) => res.json({ status: 'ok' }));

  app.get('/api/challenge', rateLimit, (req, res) => {
    const address = String(req.query.address || '');
    if (!ADDRESS_RE.test(address)) return res.status(400).json({ error: 'Invalid Sui address' });
    const nonce = crypto.randomBytes(24).toString('base64url');
    const message = `VOXX_ARCHIVE_ACCESS\nAddress: ${address}\nNonce: ${nonce}`;
    challenges.set(nonce, { address: address.toLowerCase(), message, expiresAt: Date.now() + CHALLENGE_TTL_MS });
    res.set('Cache-Control', 'no-store').json({ nonce, message });
  });

  app.post('/api/verify', rateLimit, async (req, res) => {
    const { address, message, signature } = req.body || {};
    const timeMatch = typeof message === 'string' && message.match(/\nNetwork: mainnet\nTime: ([^\n]+)$/);
    const signedAt = timeMatch ? Date.parse(timeMatch[1]) : NaN;
    const signatureId = typeof signature === 'string' ? crypto.createHash('sha256').update(signature).digest('hex') : '';
    const now = Date.now();
    for (const [id, expiresAt] of usedSignatures) if (expiresAt < now) usedSignatures.delete(id);
    if (!ADDRESS_RE.test(address || '') || !timeMatch || !Number.isFinite(signedAt) ||
        Math.abs(now - signedAt) > CHALLENGE_TTL_MS || !signatureId || usedSignatures.has(signatureId)) {
      return res.status(401).json({ error: 'Invalid, expired, or replayed wallet proof' });
    }
    try {
      const publicKey = await verifySignature(new TextEncoder().encode(message), signature, { address, client });
      if (publicKey.toSuiAddress().toLowerCase() !== address.toLowerCase()) {
        return res.status(401).json({ error: 'Wallet signature does not match address' });
      }
    } catch {
      return res.status(401).json({ error: 'Invalid wallet signature' });
    }
    try {
      if (!(await ownsNft(address))) return res.status(403).json({ error: 'Required NFT not found' });
    } catch (error) {
      console.error('[NFT VERIFY]', error);
      return res.status(502).json({ error: 'Unable to verify NFT ownership' });
    }
    usedSignatures.set(signatureId, now + CHALLENGE_TTL_MS);
    const token = jwt.sign({ address: address.toLowerCase(), jti: crypto.randomBytes(16).toString('hex') }, config.jwtSecret, {
      algorithm: 'HS256', expiresIn: SESSION_SECONDS,
    });
    res.cookie('voxx_session', token, {
      httpOnly: true, secure: config.secureCookies, sameSite: 'strict', path: '/', maxAge: SESSION_SECONDS * 1000,
    });
    res.set('Cache-Control', 'no-store').json({ ok: true });
  });

  app.get('/api/epub-key', requireSession, (req, res) => {
    res.set('Cache-Control', 'no-store').json({ epubKey: config.epubKey });
  });

  app.get('/reader.html', requireSession, (_req, res) => {
    res.set('Cache-Control', 'no-store').sendFile(config.readerPath);
  });

  app.post('/api/logout', (_req, res) => {
    res.clearCookie('voxx_session', { httpOnly: true, secure: config.secureCookies, sameSite: 'strict', path: '/' });
    res.json({ ok: true });
  });

  return app;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const config = requiredConfig();
  createApp(config).listen(config.port, () => console.log(`[VOXX Gate Server] Running on port ${config.port}`));
}

export { requiredConfig, addressOwnsNft, normalizeType };
