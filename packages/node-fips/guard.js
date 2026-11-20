'use strict';
// node-fips guard, preloaded with NODE_OPTIONS=--require (see README).
//
// These node:crypto APIs call libcrypto's built-in low-level code instead of
// OpenSSL's provider interface, so their work happens outside the Go
// Cryptographic Module. Here they throw instead.
const crypto = require('node:crypto');

function refuse(api, instead) {
  return function refused() {
    const err = new Error(`${api} is not available in node-fips: it is computed outside the FIPS module. ${instead}`);
    err.code = 'ERR_TEMPER_FIPS_UNAVAILABLE';
    throw err;
  };
}

const dh = 'Use ECDH (crypto.createECDH or crypto.diffieHellman with EC keys).';
const prime = 'Prime generation and testing are not FIPS services here.';
for (const [name, instead] of [
  ['createDiffieHellman', dh], ['createDiffieHellmanGroup', dh], ['getDiffieHellman', dh],
  ['DiffieHellman', dh], ['DiffieHellmanGroup', dh],
  ['generatePrime', prime], ['generatePrimeSync', prime], ['checkPrime', prime], ['checkPrimeSync', prime],
]) {
  crypto[name] = refuse(`crypto.${name}`, instead);
}

const ECDH = crypto.ECDH;
const pkcs8 = 'Import EC private keys as PKCS#8 (DER or PEM) with crypto.createPrivateKey, which goes through the FIPS module.';
ECDH.prototype.setPrivateKey = refuse('ECDH.setPrivateKey', pkcs8);

// An EC private key given as a JWK or as a raw scalar ('raw-private') is
// rebuilt from its scalar by libcrypto's low-level EC code (the public
// point is computed there). Every API that takes a private key accepts
// these forms, so each one is checked. The argument is copied once and the copy is what Node gets, so
// the value checked is the value used.
const isJwk = (f) => typeof f === 'string' && f.toLowerCase() === 'jwk';
const ecPrivate = (k) => k !== null && typeof k === 'object' && k.kty === 'EC' && k.d !== undefined;
const refuseJwk = refuse('an EC private key in JWK form', pkcs8);
const refuseRaw = refuse("an EC private key in 'raw-private' form", pkcs8);
const CryptoKey = globalThis.CryptoKey;
const passThrough = (v) => v === null || typeof v !== 'object' || ArrayBuffer.isView(v) ||
  v instanceof ArrayBuffer || v instanceof crypto.KeyObject ||
  (CryptoKey && v instanceof CryptoKey) || v instanceof URL;
// The fields Node reads from key options and JWKs, own or inherited, plus
// any other enumerable ones. Each is read once.
const optionFields = ['key', 'format', 'type', 'encoding', 'passphrase', 'cipher', 'properties',
  'asymmetricKeyType', 'namedCurve', 'padding', 'saltLength', 'dsaEncoding', 'context',
  'oaepHash', 'oaepLabel', 'mgf1Hash'];
const jwkFields = ['kty', 'crv', 'x', 'y', 'd', 'n', 'e', 'p', 'q', 'dp', 'dq', 'qi', 'k',
  'alg', 'use', 'key_ops', 'ext', 'pub', 'priv'];
function copyFields(obj, fields) {
  const names = new Set(fields);
  for (const name in obj) names.add(name);
  const copy = {};
  for (const name of names) {
    if (name in obj) copy[name] = obj[name];
  }
  return copy;
}
function keyArg(input) {
  if (passThrough(input)) return input;
  const copy = copyFields(input, optionFields);
  if (!passThrough(copy.key)) copy.key = copyFields(copy.key, jwkFields);
  if (isJwk(copy.format) && ecPrivate(copy.key)) refuseJwk();
  if (copy.format === 'raw-private' && typeof copy.asymmetricKeyType === 'string' &&
      copy.asymmetricKeyType.toLowerCase() === 'ec') refuseRaw();
  return copy;
}
function guardKeyAt(owner, name, index) {
  const fn = owner[name];
  if (typeof fn !== 'function') return;
  owner[name] = function (...args) {
    if (args.length > index) args[index] = keyArg(args[index]);
    return fn.apply(this, args);
  };
}
guardKeyAt(crypto, 'createPrivateKey', 0);
guardKeyAt(crypto, 'createPublicKey', 0);
guardKeyAt(crypto, 'sign', 2);
guardKeyAt(crypto, 'verify', 2);
for (const name of ['privateDecrypt', 'privateEncrypt', 'publicEncrypt', 'publicDecrypt']) guardKeyAt(crypto, name, 0);
guardKeyAt(crypto.Sign.prototype, 'sign', 0);
guardKeyAt(crypto.Verify.prototype, 'verify', 0);
guardKeyAt(crypto, 'encapsulate', 0);
guardKeyAt(crypto, 'decapsulate', 0);

const SubtleCrypto = crypto.webcrypto && Object.getPrototypeOf(crypto.webcrypto.subtle);
if (SubtleCrypto) {
  const rejectJwk = () => Promise.reject(Object.assign(new Error(
    `SubtleCrypto: an EC private key in JWK form is not available in node-fips: it is computed outside the FIPS module. ${pkcs8}`),
    { code: 'ERR_TEMPER_FIPS_UNAVAILABLE' }));
  const ecAlg = (a) => /^(ECDSA|ECDH)$/i.test(typeof a === 'string' ? a : (a && a.name) || '');
  const importKey = SubtleCrypto.importKey;
  SubtleCrypto.importKey = function (format, keyData, ...rest) {
    if (isJwk(format) && keyData !== null && typeof keyData === 'object') {
      keyData = { ...keyData };
      if (ecPrivate(keyData)) return rejectJwk();
    }
    return importKey.call(this, format, keyData, ...rest);
  };
  // unwrapKey imports after decrypting, out of reach: refuse JWK unwrapping
  // of EC keys for private-key usages.
  const unwrapKey = SubtleCrypto.unwrapKey;
  SubtleCrypto.unwrapKey = function (format, wrapped, unwrappingKey, unwrapAlgorithm, unwrappedKeyAlgorithm, extractable, keyUsages) {
    const usages = Array.isArray(keyUsages) ? [...keyUsages] : keyUsages;
    if (isJwk(format) && ecAlg(unwrappedKeyAlgorithm) && Array.isArray(usages) &&
        usages.some((u) => u === 'sign' || u === 'deriveBits' || u === 'deriveKey')) {
      return rejectJwk();
    }
    return unwrapKey.call(this, format, wrapped, unwrappingKey, unwrapAlgorithm, unwrappedKeyAlgorithm, extractable, usages);
  };
}
ECDH.convertKey = refuse('ECDH.convertKey', 'Use crypto.createPublicKey to read EC public keys.');

Object.defineProperty(globalThis, Symbol.for('temper.node-fips.guard'), { value: true });
require('node:module').syncBuiltinESMExports();
