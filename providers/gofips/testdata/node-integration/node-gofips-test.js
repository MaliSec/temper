// Node integration test for gofips (Go Cryptographic Module, CMVP #5247).
// Runs in the Temper node image (OpenSSL 4.0.3) with
// OPENSSL_CONF=openssl-gofips.cnf, so the default provider is absent.
//
// Gates:
//   1. SHA-256 known vectors through createHash.
//   2. MD5 throws; SHA-1 is served but refused in HMAC.
//   3. SHA-256 still correct afterwards; randomBytes works.
// run-node-integration.sh adds a poisoned-SHA-256 build to show
// createHash('sha256') runs the gofips code.

const crypto = require('node:crypto');

let fails = 0;
function check(cond, label) {
  console.log((cond ? 'PASS: ' : 'FAIL: ') + label);
  if (!cond) fails++;
}

const expect = {
  abc: 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
  empty: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
  abcdefgh: '9c56cc51b374c3ba189210d5b6d4bf57790d351c96c47c02190ecf1e430635ab',
};

console.log('node:', process.version, 'openssl:', process.versions.openssl);

// --- Gate 1: SHA-256 known vectors through Node's crypto API ---
function sha256hex(s) {
  return crypto.createHash('sha256').update(s).digest('hex');
}
check(sha256hex('abc') === expect.abc, 'node sha256(abc) == ba7816bf...');
check(sha256hex('') === expect.empty, 'node sha256(empty) == e3b0c442...');
check(sha256hex('abcdefgh') === expect.abcdefgh, 'node sha256(abcdefgh) == 9c56cc51...');

// --- Gate 2: fail-closed on unregistered digests ---
let md5Threw = false;
try { crypto.createHash('md5'); } catch { md5Threw = true; }
check(md5Threw, 'node createHash(md5) throws (gofips-only: unregistered, default absent)');
// SHA-1 is served as non-approved (the Go Cryptographic Module has no
// SHA-1) for non-security uses such as script cache ids and WebSocket
// handshakes. It must work and must be refused in HMAC.
let sha1Hex = null;
try { sha1Hex = crypto.createHash('sha1').update('abc').digest('hex'); } catch { sha1Hex = null; }
check(sha1Hex === 'a9993e364706816aba3e25717850c26c9cd0d89d', 'node sha1(abc) == a9993e36... (served as non-approved)');
let hmacSha1Threw = false;
try { crypto.createHmac('sha1', Buffer.alloc(32, 1)).update('abc').digest('hex'); } catch { hmacSha1Threw = true; }
check(hmacSha1Threw, 'node createHmac(sha1) throws (SHA-1 is not accepted in a MAC)');

// --- Gate 3: state intact after negative fetches + RNG available ---
check(sha256hex('abc') === expect.abc, 'node sha256 still correct after negative checks');
let rngOk = false;
try { rngOk = crypto.randomBytes(16).length === 16; } catch { rngOk = false; }
check(rngOk, 'node randomBytes works (provider RAND op backs the CSPRNG)');

console.log(fails === 0 ? 'NODE GATES PASSED' : 'NODE GATES FAILED');
process.exit(fails === 0 ? 0 : 1);
