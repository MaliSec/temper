// node-tls-negatives.js - TLS handshakes that must fail under the
// gofips-only config (OpenSSL 4.0.3), against a gofips
// server. Each must end in an error, timeout or ctx refusal, never a
// handshake:
//   1. ChaCha20-Poly1305 only
//   2. TLS 1.2 CBC suites only
//   3. TLS 1.1
//   4. X25519 only (client ctx creation refuses, no fallback)
//   5. X25519MLKEM768 only
//   6. RSA-only sigalgs (the server holds no RSA key; gofips has none)
// A baseline TLS 1.3 connection must connect and carry traffic, so the
// refusals are not a broken server.
//
// run-node-integration.sh covers the environment-level cases (missing
// provider, no crypto provider, GODEBUG=fips140=off).
const tls = require('node:tls');
// Node derives its default session-id context with SHA-1, which gofips
// serves only as non-approved. Use a SHA-256-derived one instead.
const SESSION_ID_CONTEXT = require('node:crypto').createHash('sha256').update('gofips-session-context').digest('hex').slice(0, 32);
const fs = require('node:fs');

let fails = 0;
function gate(name, cond, detail) {
  console.log((cond ? 'NEG-PASS: ' : 'NEG-FAIL: ') + name + (detail ? ' (' + detail + ')' : ''));
  if (!cond) fails++;
}

function attempt(port, opts, label, timeoutMs = 6000) {
  return new Promise((resolve) => {
    let done = false;
    let s;
    try {
      s = tls.connect({ host: '127.0.0.1', port, rejectUnauthorized: false, sessionIdContext: SESSION_ID_CONTEXT, ...opts }, () => {
        if (!done) { done = true; s.destroy(); resolve('connected'); }
      });
    } catch (e) {
      return resolve('blocked:ctx:' + String(e.message || '').slice(0, 80));
    }
    s.on('error', (e) => { if (!done) { done = true; resolve('blocked:' + String(e.message || '').split('\n')[0].slice(0, 90)); } });
    setTimeout(() => { if (!done) { done = true; s.destroy(); resolve('blocked:timeout'); } }, timeoutMs);
  });
}

async function main() {
  const KEY = fs.readFileSync((process.env.GOFIPS_CERT_DIR || '/tmp/gofips') + '/tls-key.pem');
  const CERT = fs.readFileSync((process.env.GOFIPS_CERT_DIR || '/tmp/gofips') + '/tls-cert.pem');
  const server = tls.createServer({
    sessionIdContext: SESSION_ID_CONTEXT,
    key: KEY, cert: CERT, minVersion: 'TLSv1.2', maxVersion: 'TLSv1.3',
  }, (s) => { s.on('data', (d) => s.write('echo:' + d.toString())); });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;

  // Without this control, a "blocked" result could be a dead server.
  const pos = await attempt(port, {}, 'baseline');
  gate('baseline TLS 1.3 handshake connects (positive control)', pos === 'connected', pos);

  const chacha = await attempt(port, { ciphers: 'TLS_CHACHA20_POLY1305_SHA256' }, 'chacha');
  gate('ChaCha20-only blocked (no traffic possible)', chacha.startsWith('blocked'), chacha);

  const pos12 = await attempt(port, { minVersion: 'TLSv1.2', maxVersion: 'TLSv1.2' }, 'tls12');
  gate('baseline TLS 1.2 (AES-GCM) handshake connects (positive control)', pos12 === 'connected', pos12);

  const cbc12 = await attempt(port, {
    minVersion: 'TLSv1.2', maxVersion: 'TLSv1.2',
    ciphers: 'ECDHE-ECDSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA384',
  }, 'cbc-tls12');
  gate('TLS 1.2 CBC suites blocked', cbc12.startsWith('blocked'), cbc12);

  const tls11 = await attempt(port, { minVersion: 'TLSv1.1', maxVersion: 'TLSv1.1' }, 'tls11');
  gate('TLS 1.1 blocked', tls11.startsWith('blocked'), tls11);

  const x25519 = await attempt(port, { ecdhCurve: 'X25519' }, 'x25519', 8000);
  gate('X25519-only group blocked (ctx creation refuses; no fallback)', x25519.startsWith('blocked'), x25519);

  const mlkem = await attempt(port, { ecdhCurve: 'X25519MLKEM768' }, 'mlkem', 8000);
  gate('X25519MLKEM768-only group blocked (ctx creation refuses)', mlkem.startsWith('blocked'), mlkem);

  const pss = await attempt(port, { sigalgs: 'RSA-PSS-RSA-SHA256:RSA-PKCS1-RSA-SHA256' }, 'rsa-pss', 8000);
  gate('RSA-only sigalgs blocked (no RSA signing key)', pss.startsWith('blocked'), pss);

  // Every blocked case resolved before secureConnect, so none reached
  // application data.
  let trafficOk = false;
  await new Promise((resolve) => {
    const s = tls.connect({ host: '127.0.0.1', port, rejectUnauthorized: false, sessionIdContext: SESSION_ID_CONTEXT,
      minVersion: 'TLSv1.3', maxVersion: 'TLSv1.3' }, () => {
      s.on('data', (d) => { if (d.toString().startsWith('echo:')) { trafficOk = true; s.end(); server.close(() => resolve()); } });
      s.write('traffic-probe');
    });
    s.on('error', () => { server.close(() => resolve()); });
    setTimeout(() => { server.close(() => resolve()); }, 6000);
  });
  gate('application traffic flows on the baseline connection', trafficOk);

  server.closeAll && server.closeAll();
  console.log(fails === 0 ? 'NEGATIVE GATES: ALL PASS' : 'NEGATIVE GATES: ' + fails + ' FAILED');
  process.exit(fails === 0 ? 0 : 1);
}

main().catch((e) => { console.log('FATAL:', e.message); process.exit(1); });
