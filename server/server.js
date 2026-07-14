import express from 'express';
import jwt from 'jsonwebtoken';
import { SuiGraphQLClient } from '@mysten/sui/graphql';
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

// ── Sui GraphQL Client ──
const graphqlUrl = process.env.SUI_GRAPHQL_URL ||
  (CONFIG.NETWORK === 'mainnet'
    ? 'https://graphql.mainnet.sui.io/graphql'
    : `https://graphql.${CONFIG.NETWORK}.sui.io/graphql`);

const gqlClient = new SuiGraphQLClient({ url: graphqlUrl });

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
// Client sends: { address }
// Server independently verifies NFT ownership via Sui GraphQL.
// The gate already verified the signature client-side; server double-checks on-chain state.
app.post('/api/verify', async (req, res) => {
  const { address } = req.body;

  if (!address) {
    return res.status(400).json({ error: 'Missing address' });
  }

  try {
    // Check NFT ownership via GraphQL
    const hasNft = await checkNftOwnership(address);

    if (!hasNft) {
      return res.status(403).json({ error: 'No VOXX Book Pass NFT found on this account' });
    }

    const token = jwt.sign(
      { address, verifiedAt: Date.now() },
      CONFIG.JWT_SECRET,
      { expiresIn: CONFIG.JWT_EXPIRES }
    );

    console.log(`[VERIFY] JWT issued for ${address}`);
    res.json({ token });
  } catch (err) {
    console.error('Verify error:', err);
    res.status(500).json({ error: 'Verification failed: ' + (err.message || 'Unknown error') });
  }
});

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

// ── NFT ownership check via Sui GraphQL ──
async function checkNftOwnership(address) {
  try {
    // Query objects owned by address, filtered by NFT type
    const result = await gqlClient.query({
      query: `
        query CheckNft($owner: SuiAddress!, $type: String!) {
          address(address: $owner) {
            objects(filter: { type: $type }, first: 1) {
              nodes { objectId }
            }
          }
        }
      `,
      variables: { owner: address, type: CONFIG.NFT_TYPE },
    });

    const nodes = result.data?.address?.objects?.nodes;
    if (nodes && nodes.length > 0) {
      console.log(`[NFT] Found in wallet: ${address}`);
      return true;
    }

    // Check inside Kiosks
    return await checkKiosks(address);
  } catch (err) {
    console.error('NFT ownership check error:', err);
    return false;
  }
}

// ── Kiosk scanning via GraphQL ──
async function checkKiosks(address) {
  try {
    // Get all kiosk owner caps for this address
    const kioskResult = await gqlClient.query({
      query: `
        query GetKiosks($owner: SuiAddress!) {
          address(address: $owner) {
            objects(filter: { type: "0x2::kiosk::KioskOwnerCap" }) {
              nodes {
                objectId
                asMoveObject {
                  contents {
                    json
                  }
                }
              }
            }
          }
        }
      `,
      variables: { owner: address },
    });

    const kioskCaps = kioskResult.data?.address?.objects?.nodes || [];
    if (kioskCaps.length === 0) return false;

    for (const cap of kioskCaps) {
      try {
        const json = cap.asMoveObject?.contents?.json;
        if (!json) continue;
        const kioskId = json.for;
        if (!kioskId) continue;

        // Check items in this kiosk
        const itemsResult = await gqlClient.query({
          query: `
            query GetKioskItems($kioskId: SuiAddress!, $nftType: String!) {
              address(address: $kioskId) {
                dynamicFields {
                  nodes {
                    name {
                      json
                    }
                    value {
                      ... on MoveValue {
                        json
                      }
                    }
                  }
                }
              }
              objects(filter: { type: $nftType, owner: $kioskId }, first: 10) {
                nodes { objectId }
              }
            }
          `,
          variables: { kioskId, nftType: CONFIG.NFT_TYPE },
        });

        const items = itemsResult.data?.objects?.nodes;
        if (items && items.length > 0) {
          console.log(`[NFT] Found in kiosk ${kioskId} for ${address}`);
          return true;
        }
      } catch (e) {
        // Skip individual kiosk errors
      }
    }

    return false;
  } catch (err) {
    console.error('Kiosk scan error:', err);
    return false;
  }
}

// ── Start ──
app.listen(CONFIG.PORT, () => {
  console.log(`[VOXX Gate Server] Running on port ${CONFIG.PORT}`);
  console.log(`[VOXX Gate Server] Network: ${CONFIG.NETWORK}`);
  console.log(`[VOXX Gate Server] NFT: ${CONFIG.NFT_TYPE}`);
  console.log(`[VOXX Gate Server] EPUB: ${existsSync(CONFIG.EPUB_PATH) ? 'found' : 'MISSING!'}`);
  console.log(`[VOXX Gate Server] GraphQL: ${graphqlUrl}`);
});
