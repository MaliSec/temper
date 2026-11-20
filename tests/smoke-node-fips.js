// Smoke test for the node-fips image. Any failed assert exits non-zero.
//
// Checks that node:crypto and TLS are served by gofips (the Go Cryptographic
// Module), that non-approved algorithms are refused, and that neither the
// default nor the legacy OpenSSL provider is loaded.
"use strict";
const assert = require("node:assert");
const crypto = require("node:crypto");
const fs = require("node:fs");
const tls = require("node:tls");

assert.strictEqual(process.env.OPENSSL_CONF, "/etc/ssl/openssl-gofips.cnf");
assert.strictEqual(process.env.GODEBUG, "fips140=on");

const hex = (alg, data, opts) => crypto.createHash(alg, opts).update(data).digest("hex");
assert.strictEqual(hex("sha256", "abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
assert.strictEqual(hex("sha3-256", "abc"), "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");
assert.strictEqual(hex("shake256", "abc", { outputLength: 32 }), "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739");
assert.strictEqual(hex("sha384", "abc"), "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7");
assert.strictEqual(hex("sha512", "abc"), "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
assert.strictEqual(hex("sha3-224", "abc"), "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf");
assert.strictEqual(hex("sha3-384", "abc"), "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25");
assert.strictEqual(hex("sha3-512", "abc"), "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0");
assert.strictEqual(hex("shake128", "abc", { outputLength: 16 }), "5881092dd818bf5cf8a3ddb793fbcba7");
assert.strictEqual(hex("sha1", "abc"), "a9993e364706816aba3e25717850c26c9cd0d89d", "SHA-1 for non-security uses");
assert.strictEqual(crypto.createHmac("sha256", "k".repeat(32)).update("abc").digest().length, 32, "HMAC-SHA-256");
assert.strictEqual(crypto.createHmac("sha3-256", "k".repeat(32)).update("abc").digest("hex"),
  "e444577fc23e76dc5677bcaa53ad9a4fd784e1b3dd299f4bfc3e53555f841e58");
assert.strictEqual(
  crypto.pbkdf2Sync("password", "0123456789abcdef", 1000, 32, "sha256").toString("hex"),
  "8514638175a45bc45eb1f22f04ff7d27f4f8be480498c455ff4b494ce8d1e7d2");
assert.strictEqual(Buffer.from(crypto.hkdfSync("sha3-256", "k".repeat(32), "0123456789abcdef", "info", 32)).toString("hex"),
  "019cf79c19603f3e2f4bbc3147851b8bc6d2d50bc5f548312bd59d9c497ee65e");
const ec = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const sig = crypto.sign("sha256", Buffer.from("abc"), ec.privateKey);
assert.ok(crypto.verify("sha256", Buffer.from("abc"), ec.publicKey, sig));
assert.strictEqual(crypto.randomBytes(16).length, 16);
assert.match(crypto.randomUUID(), /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
assert.strictEqual(globalThis.crypto.getRandomValues(new Uint8Array(16)).length, 16);
const sig512 = crypto.sign("sha512", Buffer.from("abc"), ec.privateKey);
assert.ok(crypto.verify("sha512", Buffer.from("abc"), ec.publicKey, sig512), "ECDSA with SHA-512");
for (const [alg, keyLen, ivLen] of [["aes-128-gcm", 16, 12], ["aes-256-gcm", 32, 12], ["aes-128-cbc", 16, 16], ["aes-256-cbc", 32, 16]]) {
  const key = crypto.randomBytes(keyLen), iv = crypto.randomBytes(ivLen), gcm = alg.endsWith("gcm");
  const enc = crypto.createCipheriv(alg, key, iv);
  const ct = Buffer.concat([enc.update("temper-fips"), enc.final()]);
  const dec = crypto.createDecipheriv(alg, key, iv);
  if (gcm) dec.setAuthTag(enc.getAuthTag());
  assert.strictEqual(Buffer.concat([dec.update(ct), dec.final()]).toString(), "temper-fips", `${alg} round trip`);
}

const p384 = crypto.generateKeyPairSync("ec", { namedCurve: "P-384" });
const sig384 = crypto.sign("sha384", Buffer.from("abc"), p384.privateKey);
assert.ok(crypto.verify("sha384", Buffer.from("abc"), p384.publicKey, sig384));
const peer = crypto.createECDH("secp384r1");
const self = crypto.createECDH("secp384r1");
peer.generateKeys();
self.generateKeys();
assert.ok(self.computeSecret(peer.getPublicKey()).equals(peer.computeSecret(self.getPublicKey())));

// RSA-2048 verification: a fixed key and signatures made with the default provider.
const rsaPub = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAixOJlmquFYVDjjWblTCeq+LDjI+asHEENg2bRfWwqxgxtF+C51YOIekTIGMvCYxT0zepnH9h/wrJs/mUCFbKSOWvjlwLkJ+Zqc/4gf09GbJ64nunvc3euPNmuiB5E2645rLwmJRSRbROLIPnId9xWUrBey6mg9vhB+8STjUFm5+8GpEyLMx1/wvVMP08xty5SwVKGqzLR3HIwu8drKiRqsp6NUtUMKJGk7YhC4xI8+GVXwcHp4JkNquhq6dXMdssVbbiHtzyhMIMwNypCBGP/gZnyiLlvGr8orCLHUCY6bHmmrl5OP9Sn+B7z+6QZpNU8CpzPJPfHXQXwGphhEV1GwIDAQAB\n-----END PUBLIC KEY-----\n";
const msg = Buffer.from("temper-fips");
const pkcs1 = Buffer.from("ECC93O/27miBBFBunDSaJOHxqjjFrDXQ59DUbplzZxPOlMSM95KQM020QYznuoQ1isjWdQoOxEE02KZgbyufZQWk0FqU9JT/KSeQs7j1bGLpiHbe9IskU/cIPmBh91saa84jMWbZBAfLbeNUFLyO5KzXOIYN1OiMoarXa+U3h4QXNR7XnSGzs/qBMtxJKpxMgsh3oaFZQANeibMRgh8vx6/3RPeXnAkU7RiK0DeCQ8YlC9f1VS7Kmk1zhUo/Y2gHshRDoDVYZ3x3AbI7xKGblPLcd8YR3/PvLOmKKm+OTfXkQbpN4kAGRzE3Jd87PJrO4Rs6zsNpfqVKXSqTAQfaHA==", "base64");
const pss = Buffer.from("KfX9lW0qByGpZyGvkB8/8BUu/EzM2HS5eva4yT7XSc7dlnNub3IfwiNwCjzXeUkweG8fSauKf6AM/yaluHBkK3UiCh80kXcvkgZnQytivM4p//ao/OaJIPa2c43prsHpXBU4dvV1l/UdI0hKxL6Ps3Hc9h0aTl629+WxtMttaj+DR28tveHlkT/FK1qwhTZbyAlu3Xpuz+OAfk1U1ju8PgtE61jgpL+KaFoeh5DbpRzaL4UbP/Nm/dEksEXHR9c+aCUORKmiLChEPtHc4qxDFPS6oAKSprVzvv2lkpIs4psIzSxTH8q2B3WQbPA2d5SYWYRYsjxC5eif1u/EE7/cOw==", "base64");
assert.ok(crypto.verify("sha256", msg, rsaPub, pkcs1), "RSA PKCS#1 v1.5 verify");
assert.ok(crypto.verify("sha256", msg, { key: rsaPub, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 }, pss),
  "RSA-PSS verify");
assert.ok(!crypto.verify("sha256", Buffer.from("temper-fipz"), rsaPub, pkcs1), "RSA verify of a changed message");

// A refusal is a plain Error from OpenSSL, or (Node 26) a TypeError saying
// the type is not supported, which Node decides by asking OpenSSL. Other
// TypeErrors and RangeErrors are usage mistakes and would make a refusal
// check pass vacuously.
const refused = (label, fn) => assert.throws(fn,
  (e) => e instanceof Error && !(e instanceof RangeError)
    && (!(e instanceof TypeError) || /not supported|supported key type/i.test(e.message)), `${label} must be refused`);
refused("md5", () => crypto.createHash("md5"));
refused("md4", () => crypto.createHash("md4"));
refused("ripemd160", () => crypto.createHash("ripemd160"));
refused("sha224", () => crypto.createHash("sha224"));
refused("sha512-256", () => crypto.createHash("sha512-256"));
refused("blake2b512", () => crypto.createHash("blake2b512"));
refused("blake2s256", () => crypto.createHash("blake2s256"));
refused("HMAC with a key under 112 bits", () => crypto.createHmac("sha256", "short").update("x").digest());
refused("ChaCha20-Poly1305", () => crypto.createCipheriv("chacha20-poly1305", Buffer.alloc(32), Buffer.alloc(12), { authTagLength: 16 }));
refused("AES-CTR", () => crypto.createCipheriv("aes-256-ctr", Buffer.alloc(32), Buffer.alloc(16)));
// Node reports an unavailable scrypt as invalid parameters (a RangeError).
assert.throws(() => crypto.scryptSync("password", "0123456789abcdef", 32), /unsupported/, "scrypt must be refused");
refused("pbkdf2 with an 8-byte salt", () => crypto.pbkdf2Sync("password", "01234567", 1000, 32, "sha256"));
refused("pbkdf2 with SHA-1", () => crypto.pbkdf2Sync("password", "0123456789abcdef", 1000, 32, "sha1"));
refused("pbkdf2 with a 104-bit derived key", () => crypto.pbkdf2Sync("password", "0123456789abcdef", 1000, 13, "sha256"));
refused("RSA key generation", () => crypto.generateKeyPairSync("rsa", { modulusLength: 2048 }));
refused("RSA encryption", () => crypto.publicEncrypt(rsaPub, Buffer.from("x")));
refused("RSA decryption", () => crypto.privateDecrypt(fs.readFileSync("/tls/rsa-key.pem"), fs.readFileSync("/tls/rsa-oaep.bin")));
refused("RSA signing", () => crypto.sign("sha256", Buffer.from("x"), fs.readFileSync("/tls/rsa-key.pem")));
refused("a TLS context with an RSA private key",
  () => tls.createSecureContext({ key: fs.readFileSync("/tls/rsa-key.pem"), cert: fs.readFileSync("/tls/rsa-cert.pem") }));
refused("P-521", () => crypto.generateKeyPairSync("ec", { namedCurve: "P-521" }));
refused("finite-field DH key pairs", () => crypto.generateKeyPairSync("dh", { group: "modp14" }));
refused("Ed25519", () => crypto.generateKeyPairSync("ed25519"));

// The guard (temper-node-fips): APIs computed outside the module throw.
assert.ok(globalThis[Symbol.for("temper.node-fips.guard")], "node-fips guard not loaded (NODE_OPTIONS)");
const guarded = (label, fn) => assert.throws(fn, { code: "ERR_TEMPER_FIPS_UNAVAILABLE" }, `${label} must be refused by the guard`);
guarded("getDiffieHellman", () => crypto.getDiffieHellman("modp14"));
guarded("createDiffieHellman", () => crypto.createDiffieHellman(2048));
guarded("generatePrimeSync", () => crypto.generatePrimeSync(64));
guarded("checkPrimeSync", () => crypto.checkPrimeSync(7n));
guarded("ECDH.setPrivateKey", () => crypto.createECDH("prime256v1").setPrivateKey(Buffer.alloc(32, 1)));
guarded("ECDH.convertKey", () => crypto.ECDH.convertKey(p384.publicKey.export({ format: "jwk" }).x, "secp384r1"));
const ecPair = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" }), ecKey = ecPair.privateKey;
guarded("createPrivateKey with an EC private JWK", () => crypto.createPrivateKey({ key: ecKey.export({ format: "jwk" }), format: "jwk" }));
const ecJwk = { key: ecKey.export({ format: "jwk" }), format: "jwk" };
guarded("createPublicKey with an EC private JWK", () => crypto.createPublicKey(ecJwk));
guarded("sign with an EC private JWK", () => crypto.sign("sha256", Buffer.from("x"), ecJwk));
guarded("verify with an EC private JWK", () => crypto.verify("sha256", Buffer.from("x"), ecJwk, Buffer.alloc(64)));
guarded("createSign().sign with an EC private JWK", () => crypto.createSign("sha256").update("x").sign(ecJwk));
guarded("createVerify().verify with an EC private JWK", () => crypto.createVerify("sha256").update("x").verify(ecJwk, Buffer.alloc(64)));
guarded("privateDecrypt with an EC private JWK", () => crypto.privateDecrypt(ecJwk, Buffer.alloc(32)));
if (crypto.decapsulate) guarded("decapsulate with an EC private JWK", () => crypto.decapsulate(ecJwk, Buffer.alloc(65)));
if (crypto.encapsulate) guarded("encapsulate with an EC private JWK", () => crypto.encapsulate(ecJwk));
// The alternative the guard points to: PKCS#8, imported through the provider.
const der = ecKey.export({ format: "der", type: "pkcs8" });
assert.strictEqual(crypto.createPrivateKey({ key: der, format: "der", type: "pkcs8" }).asymmetricKeyDetails.namedCurve, "prime256v1");
crypto.createPublicKey({ key: ecPair.publicKey.export({ format: "jwk" }), format: "jwk" }); // public JWKs are fine
// Options inherited from a prototype reach Node through the guard.
assert.ok(crypto.verify("sha256", Buffer.from("abc"), Object.create({ key: ec.publicKey }), sig), "inherited key options");
guarded("an inherited EC private JWK", () => crypto.sign("sha256", Buffer.from("x"), Object.create(ecJwk)));
guarded("createPrivateKey with a raw EC private scalar", () => crypto.createPrivateKey({
  key: Buffer.from(ecJwk.key.d, "base64url"), format: "raw-private", asymmetricKeyType: "ec", namedCurve: "P-256" }));
refused("X25519", () => crypto.generateKeyPairSync("x25519"));

const maps = fs.readFileSync("/proc/self/maps", "utf8");
assert.ok(maps.includes("gofips.so"), "gofips provider not loaded");
assert.ok(!maps.includes("legacy.so"), "legacy provider loaded");

// Without OPENSSL_CONF, the default openssl.cnf is the gofips-only config:
// the child computes SHA-256 in gofips and OpenSSL refuses MD5.
const childProbe = `const c = require("crypto");
const out = { sha256: c.createHash("sha256").update("abc").digest("hex"),
  gofips: require("fs").readFileSync("/proc/self/maps", "utf8").includes("gofips.so") };
try { c.createHash("md5"); out.md5 = "computed"; } catch (e) { out.md5 = e.code; }
console.log(JSON.stringify(out));`;
const child = require("child_process").spawnSync(process.execPath, ["-e", childProbe], { env: {}, encoding: "utf8" });
assert.strictEqual(child.status, 0, `child started without OPENSSL_CONF: ${child.stderr}`);
assert.deepStrictEqual(JSON.parse(child.stdout),
  { sha256: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", gofips: true, md5: "ERR_OSSL_EVP_UNSUPPORTED" },
  "child started without OPENSSL_CONF");

// --openssl-legacy-provider loads legacy.so, which libcrypto's package
// requires, but it adds no usable algorithm: the legacy provider's own
// algorithms and every listed one stay as without the flag.
const usable = (flags) => require("child_process").spawnSync(process.execPath, [...flags, "-e", `const c = require("crypto");
const hash = (n) => { try { c.createHash(n, /^shake/.test(n) ? { outputLength: 32 } : undefined).update("x").digest(); return true; } catch { return false; } };
const cipher = (n, key, iv) => { try { const x = c.createCipheriv(n, Buffer.alloc(key), iv ? Buffer.alloc(iv) : null); x.update("x"); x.final(); return true; } catch { return false; } };
const legacy = { md4: hash("md4"), md5: hash("md5"), ripemd160: hash("ripemd160"), whirlpool: hash("whirlpool"),
  "bf-cbc": cipher("bf-cbc", 16, 8), "cast5-cbc": cipher("cast5-cbc", 16, 8), "des-ede3-cbc": cipher("des-ede3-cbc", 24, 8),
  "des-cbc": cipher("des-cbc", 8, 8), rc4: cipher("rc4", 16, 0), "seed-cbc": cipher("seed-cbc", 16, 16) };
const h = c.getHashes().filter(hash);
const k = c.getCiphers().filter((n) => { try { const i = c.getCipherInfo(n); return cipher(n, i.keyLength, i.ivLength); } catch { return false; } });
console.log(JSON.stringify({ legacy, h, k }));`], { encoding: "utf8" });
const plain = usable([]), legacy = usable(["--openssl-legacy-provider"]);
assert.ok(plain.status === 0 && legacy.status === 0, plain.stderr + legacy.stderr);
assert.ok(JSON.parse(plain.stdout).h.includes("sha256"), "usable-algorithm probe found no SHA-256");
assert.ok(Object.values(JSON.parse(legacy.stdout).legacy).every((v) => v === false),
  `legacy algorithms usable with --openssl-legacy-provider: ${legacy.stdout}`);
assert.strictEqual(legacy.stdout, plain.stdout, "--openssl-legacy-provider adds usable algorithms");

// A public endpoint with an RSA certificate and an RSA chain, verified.
function connect(opts) {
  return new Promise((resolve, reject) => {
    const s = tls.connect(opts, () => {
      s.once("data", (d) => { s.end(); resolve({ s, d: d.toString() }); });
    });
    s.on("session", (sess) => { opts.onSession?.(sess); });
    s.on("error", reject);
  });
}

// A local TLS 1.3 server with Node's defaults (session tickets on), then a
// resumed connection: the PSK binder is an HMAC signature in gofips.
async function localTls() {
  const key = fs.readFileSync("/tls/key.pem"), cert = fs.readFileSync("/tls/cert.pem");
  const server = tls.createServer({ key, cert }, (c) => c.end("hello"));
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const base = { host: "127.0.0.1", port: server.address().port, servername: "localhost", ca: cert };
  let session;
  const first = await connect({ ...base, onSession: (s) => { session = s; } });
  assert.strictEqual(first.d, "hello", "local TLS server with default options");
  assert.ok(first.s.getProtocol() === "TLSv1.3" && !first.s.isSessionReused());
  await new Promise((r) => setTimeout(r, 100));
  assert.ok(session, "no session ticket received");
  const again = await connect({ ...base, session });
  assert.ok(again.s.isSessionReused(), "TLS 1.3 session not resumed");
  assert.strictEqual(again.d, "hello");
  const t12 = await connect({ ...base, maxVersion: "TLSv1.2" });
  assert.ok(t12.s.getProtocol() === "TLSv1.2" && /GCM/.test(t12.s.getCipher().name) && t12.d === "hello", "TLS 1.2 with AES-GCM");
  // Wolfi's OpenSSL build has no TLS 1.1 (as in the plain node image).
  await assert.rejects(connect({ ...base, minVersion: "TLSv1.1", maxVersion: "TLSv1.1" }), undefined, "TLS 1.1 must be unavailable");
  server.close();
  // Both ends offer a TLS 1.2 CBC suite (overriding --tls-cipher-list), so
  // the refusal comes from the provider, not from a missing shared suite.
  const cbc = "ECDHE-ECDSA-AES128-SHA256";
  const cbcServer = tls.createServer({ key, cert, ciphers: cbc, maxVersion: "TLSv1.2" }, (c) => c.end("hello"));
  cbcServer.on("tlsClientError", () => {});
  await new Promise((r) => cbcServer.listen(0, "127.0.0.1", r));
  await assert.rejects(connect({ ...base, port: cbcServer.address().port, maxVersion: "TLSv1.2", ciphers: cbc }),
    (e) => !/no (shared )?cipher|NO_SHARED_CIPHER|NO_CIPHERS/i.test(`${e.code} ${e.message}`), "a TLS 1.2 CBC suite must be refused by the provider");
  cbcServer.close();
}

// WebCrypto: an EC private JWK is refused by the guard, on import and on unwrap.
async function webcrypto() {
  const subtle = globalThis.crypto.subtle;
  const jwk = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey.export({ format: "jwk" });
  await assert.rejects(subtle.importKey("jwk", jwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]),
    { code: "ERR_TEMPER_FIPS_UNAVAILABLE" }, "WebCrypto importKey of an EC private JWK must be refused");
  const kw = await subtle.generateKey({ name: "AES-KW", length: 256 }, false, ["wrapKey", "unwrapKey"]);
  await assert.rejects(subtle.unwrapKey("jwk", new Uint8Array(40), kw, "AES-KW", { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]),
    { code: "ERR_TEMPER_FIPS_UNAVAILABLE" }, "WebCrypto unwrapKey of an EC private JWK must be refused");
  const pub = await subtle.importKey("jwk", { kty: "EC", crv: jwk.crv, x: jwk.x, y: jwk.y },
    { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
  assert.strictEqual(pub.type, "public", "WebCrypto import of an EC public JWK");
  // A CryptoKey passed to node:crypto reaches Node unchanged.
  const pair = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const s = crypto.sign("sha256", Buffer.from("abc"), { key: pair.privateKey, dsaEncoding: "ieee-p1363" });
  assert.ok(crypto.verify("sha256", Buffer.from("abc"), { key: pair.publicKey, dsaEncoding: "ieee-p1363" }, s), "sign and verify with a CryptoKey");
  assert.strictEqual(crypto.createPublicKey(pair.privateKey).type, "public", "createPublicKey from a CryptoKey");
}

// A public endpoint, chain verified, failing after 10 seconds.
function publicConnect(host, opts = {}) {
  return new Promise((resolve, reject) => {
    const s = tls.connect({ host, port: 443, servername: host, ...opts }, () => resolve(s));
    s.setTimeout(10000, () => s.destroy(new Error(`TLS to ${host} timed out`)));
    s.on("error", reject);
  });
}

async function publicTls() {
  if (process.env.SMOKE_NO_NETWORK === "1") return "public TLS SKIPPED (SMOKE_NO_NETWORK=1)";
  const s = await publicConnect("packages.wolfi.dev");
  assert.ok(s.authorized && s.getProtocol() === "TLSv1.3", "TLS 1.3 to packages.wolfi.dev, chain verified");
  s.destroy();
  const n = await publicConnect("registry.npmjs.org", { maxVersion: "TLSv1.2" });
  assert.ok(n.authorized && n.getProtocol() === "TLSv1.2", "TLS 1.2 to registry.npmjs.org, chain verified");
  n.destroy();
  return "TLS 1.3 to packages.wolfi.dev, TLS 1.2 to registry.npmjs.org";
}

(async () => {
  await localTls();
  await webcrypto();
  const pub = await publicTls();
  console.log(`smoke ok: node-fips ${process.version} (gofips serves crypto, RSA verify, P-384, local TLS 1.3 server with tickets and resumption, local TLS 1.2 (GCM; CBC refused), ${pub}; md5, RSA private keys, X25519, short-salt pbkdf2 refused; no TLS 1.1 in the base; guard refuses DH, primes, ECDH.setPrivateKey, EC private JWKs; no legacy)`);
})().catch((e) => { console.error(e); process.exit(1); });
