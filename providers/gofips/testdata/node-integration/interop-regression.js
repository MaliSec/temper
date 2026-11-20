// interop-regression.js - cross-provider TLS 1.3 interop (ECDSA P-256,
// tickets on), both directions:
//   A. gofips Node client -> default-provider OpenSSL server
//   B. default-provider client -> gofips Node server
// The gofips side uses the gofips-only OPENSSL_CONF; the default side
// runs with it unset. Each run does a handshake and an echo.
//
// One process cannot hold both provider sets, so each invocation plays
// one role (ROLE=server-gofips|client-gofips|client-default);
// run-interop-regression.sh starts the peer in another container.
const tls = require('node:tls');
// Node derives its default session-id context with SHA-1, which gofips
// serves only as non-approved. Use a SHA-256-derived one instead.
const SESSION_ID_CONTEXT = require('node:crypto').createHash('sha256').update('gofips-session-context').digest('hex').slice(0, 32);
const fs = require('node:fs');
const net = require('node:net');

const ROLE = process.env.ROLE;
const PORT = parseInt(process.env.PORT || '9443', 10);
const HOST = process.env.HOST || '127.0.0.1';
const CERT_DIR = process.env.GOFIPS_CERT_DIR || '/tmp/gofips';
const KEY = fs.readFileSync(CERT_DIR + '/tls-key.pem');
const CERT = fs.readFileSync(CERT_DIR + '/tls-cert.pem');

function serverSide(useGofips) {
  return new Promise((resolve, reject) => {
    const srv = tls.createServer({
      sessionIdContext: SESSION_ID_CONTEXT,
      key: KEY, cert: CERT, minVersion: 'TLSv1.3', maxVersion: 'TLSv1.3',
    }, (s) => {
      s.on('data', (d) => s.write('srv-echo:' + d.toString()));
    });
    srv.listen(PORT, '0.0.0.0', () => resolve(srv));
    srv.on('error', reject);
  });
}

function clientSide(port) {
  return new Promise((resolve, reject) => {
    // sessionIdContext only for gofips roles: a default-provider client
    // with an explicit context fails after the handshake (bad record mac).
    const s = tls.connect({ host: HOST, port, rejectUnauthorized: false, sessionIdContext: ROLE && ROLE.indexOf('gofips') >= 0 ? SESSION_ID_CONTEXT : undefined,
      minVersion: 'TLSv1.3', maxVersion: 'TLSv1.3' }, () => {
      const proto = s.getProtocol();
      const cipher = s.getCipher() && s.getCipher().name;
      s.write('hello-from-client');
      let got = '';
      const t = setTimeout(() => { s.destroy(); reject(new Error('echo timeout')); }, 8000);
      s.on('data', (d) => {
        got += d.toString();
        if (got.startsWith('srv-echo:')) { clearTimeout(t); s.end(); resolve({ proto, cipher, echoed: got }); }
      });
      s.on('error', (e) => { clearTimeout(t); reject(e); });
    });
    s.on('error', (e) => reject(e));
  });
}

async function main() {
  if (ROLE === 'server-gofips') {
    const srv = await serverSide(true);
    console.log('SERVER-UP gofips (conf=' + (process.env.OPENSSL_CONF || 'default') + ')');
    setTimeout(() => process.exit(0), 30000);
  } else if (ROLE === 'client-gofips') {
    const r = await clientSide(PORT);
    console.log('CLIENT-OK gofips proto=' + r.proto + ' cipher=' + r.cipher);
    console.log('ECHO=' + r.echoed);
    process.exit(0);
  } else if (ROLE === 'client-default') {
    const r = await clientSide(PORT);
    console.log('CLIENT-OK default proto=' + r.proto + ' cipher=' + r.cipher);
    console.log('ECHO=' + r.echoed);
    process.exit(0);
  } else {
    console.log('ROLE unset');
    process.exit(2);
  }
}
main().catch((e) => { console.log('INTEROP-FAIL: ' + String(e.message || e).split('\n')[0].slice(0, 160)); process.exit(1); });
