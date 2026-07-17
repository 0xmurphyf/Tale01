import test from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { fileURLToPath } from 'node:url';
import { createApp, requiredConfig } from './server.js';

const address = `0x${'1'.repeat(64)}`;
const config = {
  jwtSecret: 'j'.repeat(64),
  epubKey: Buffer.alloc(32, 7).toString('base64'),
  nftType: '0x1::test::Nft', rpcUrl: 'unused', readerPath: fileURLToPath(new URL('../reader.html', import.meta.url)),
  secureCookies: false,
};

async function withServer(dependencies, fn) {
  const server = createApp(config, dependencies).listen(0);
  await once(server, 'listening');
  try { await fn(`http://127.0.0.1:${server.address().port}`); }
  finally { await new Promise((resolve) => server.close(resolve)); }
}

function proof() {
  return { address, message: `Dark Transcendence\nNFT access verification\nNetwork: mainnet\nTime: ${new Date().toISOString()}`, signature: `sig-${crypto.randomUUID()}` };
}

const matchingKey = { toSuiAddress: () => address };

test('production secrets fail closed', () => {
  assert.throws(() => requiredConfig({}), /JWT_SECRET/);
  assert.throws(() => requiredConfig({ JWT_SECRET: 'x'.repeat(32) }), /EPUB_KEY/);
});

test('reader and EPUB key require an authenticated cookie', async () => {
  await withServer({ verifySignature: async () => matchingKey, ownsNft: async () => true }, async (base) => {
    assert.equal((await fetch(`${base}/reader.html`)).status, 401);
    assert.equal((await fetch(`${base}/api/epub-key`)).status, 401);
  });
});

test('server rejects a signed wallet that does not own the NFT', async () => {
  await withServer({ verifySignature: async () => matchingKey, ownsNft: async () => false }, async (base) => {
    const response = await fetch(`${base}/api/verify`, {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(proof()),
    });
    assert.equal(response.status, 403);
    assert.equal(response.headers.get('set-cookie'), null);
  });
});

test('signature verification receives address and Sui client context', async () => {
  let options;
  await withServer({
    verifySignature: async (_message, _signature, received) => { options = received; return matchingKey; },
    ownsNft: async () => false,
  }, async (base) => {
    await fetch(`${base}/api/verify`, {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(proof()),
    });
    assert.equal(options.address, address);
    assert.ok(options.client);
  });
});

test('chain lookup failures are not reported as bad signatures', async () => {
  await withServer({ verifySignature: async () => matchingKey, ownsNft: async () => { throw new Error('RPC unavailable'); } }, async (base) => {
    const response = await fetch(`${base}/api/verify`, {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(proof()),
    });
    assert.equal(response.status, 502);
    assert.equal((await response.json()).error, 'Unable to verify NFT ownership');
  });
});

test('valid proof creates HttpOnly session and cannot be replayed', async () => {
  await withServer({ verifySignature: async () => matchingKey, ownsNft: async () => true }, async (base) => {
    const body = proof();
    const first = await fetch(`${base}/api/verify`, {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body),
    });
    assert.equal(first.status, 200);
    const cookie = first.headers.get('set-cookie');
    assert.match(cookie, /voxx_session=/);
    assert.match(cookie, /HttpOnly/i);
    assert.match(cookie, /SameSite=Strict/i);
    const sessionCookie = cookie.split(';')[0];
    const keyResponse = await fetch(`${base}/api/epub-key`, { headers: { cookie: sessionCookie } });
    assert.equal(keyResponse.status, 200);
    assert.equal((await keyResponse.json()).epubKey, config.epubKey);
    assert.equal((await fetch(`${base}/reader.html`, { headers: { cookie: sessionCookie } })).status, 200);
    const replay = await fetch(`${base}/api/verify`, {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body),
    });
    assert.equal(replay.status, 401);
  });
});
