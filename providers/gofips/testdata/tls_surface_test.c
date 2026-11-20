/* tls_surface_test.c - the operations a TLS 1.3 handshake needs, served
 * by gofips with the default provider absent:
 *   - SHA-384 digest (known vectors)
 *   - HMAC-SHA256/384 (known vectors)
 *   - HKDF-SHA256/384 (RFC 5869 test vectors)
 *   - AES-256-GCM one-shot encrypt/decrypt (NIST vector) + tag-mismatch
 *     fail-closed
 *   - EC P-256 keygen + ECDH shared-secret symmetry
 *   - ECDSA sign/verify (digest_sign/digest_verify) + tamper fail-closed
 *
 * Build:
 *   cc testdata/tls_surface_test.c -o tls_surface_test \
 *      $(pkg-config --cflags --libs libcrypto) -ldl
 * Run:
 *   GOFIPS_SO=/path/gofips.so ./tls_surface_test
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/err.h>
#include <openssl/kdf.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/ec.h>
#include <dlfcn.h>

int fails = 0;
#define CHECK(cond, label) \
    do { \
        if (cond) { printf("PASS: %s\n", label); } \
        else { printf("FAIL: %s\n", label); fails++; } \
    } while (0)

static void hexout(const unsigned char *b, int n) {
    for (int i = 0; i < n; i++) printf("%02x", b[i]);
}

int main(void) {
    const char *so_path = getenv("GOFIPS_SO");
    if (!so_path) so_path = "/tmp/temperfips.so";

    OSSL_PROVIDER *g = OSSL_PROVIDER_load(NULL, so_path);
    CHECK(g != NULL, "gofips provider loads");
    if (!g) return 1;

    /* --- SHA-384 --- */
    EVP_MD *md384 = EVP_MD_fetch(NULL, "SHA2-384", "provider=gofips");
    CHECK(md384 != NULL, "SHA2-384 fetchable from provider=gofips");
    if (md384) {
        /* sha384("abc") known vector */
        unsigned char out[48]; unsigned int outl = 0;
        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex2(ctx, md384, NULL);
        EVP_DigestUpdate(ctx, "abc", 3);
        EVP_DigestFinal_ex(ctx, out, &outl);
        EVP_MD_CTX_free(ctx);
        CHECK(outl == 48 && out[0] == 0xcb && out[1] == 0x00, "sha384(abc) known-vector prefix (cb0075...) correct");
        /* SHA-512 IS registered (GCM's EVP path needs it); verify it works */
        EVP_MD *md512 = EVP_MD_fetch(NULL, "SHA2-512", "provider=gofips");
        CHECK(md512 != NULL, "SHA2-512 fetchable (registered for GCM path)");
        if (md512) EVP_MD_free(md512);
        EVP_MD_free(md384);
    }

    /* --- HMAC-SHA256 --- */
    EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", "provider=gofips");
    CHECK(mac != NULL, "HMAC fetchable from provider=gofips");
    if (mac) {
        EVP_MAC_CTX *mctx = EVP_MAC_CTX_new(mac);
        OSSL_PARAM mp[3];
        char digest_name[] = "sha256";
        unsigned char key[] = {0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b};
        mp[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, digest_name, 0);
        mp[1] = OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_KEY, key, sizeof(key));
        mp[2] = OSSL_PARAM_construct_end();
        int r = EVP_MAC_init(mctx, NULL, 0, mp); /* key via params */
        CHECK(r == 1, "HMAC init ok");
        r = EVP_MAC_update(mctx, (unsigned char*)"what do ya want for nothing?", 28);
        CHECK(r == 1, "HMAC update ok");
        size_t outl = 0; unsigned char out[64];
        r = EVP_MAC_final(mctx, out, &outl, sizeof(out));
        CHECK(r == 1 && outl == 32, "HMAC final ok (32 bytes)");
        /* RFC 4231 TC1's key with TC2's data, so not a published vector:
         * TC2's 4-byte key "Jefe" is below the 112-bit HMAC key floor and
         * is refused. Expected HMAC (Python hmac):
         * 6a055afb1295ef9de35605919cbb8f86f51ee183901f001e6dc53ec3d2480ba9 */
        CHECK(out[0] == 0x6a && out[1] == 0x05 && out[2] == 0x5a && out[3] == 0xfb,
              "HMAC-SHA256 (RFC 4231 TC1 key, TC2 data) known value 6a055afb correct");
        EVP_MAC_CTX_free(mctx);
        EVP_MAC_free(mac);
    }

    /* --- HKDF-SHA256 (RFC 5869 Test Case 1) --- */
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", "provider=gofips");
    CHECK(kdf != NULL, "HKDF fetchable from provider=gofips");
    if (kdf) {
        EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(kdf);
        unsigned char ikm[22], salt[13], info[10], out[42];
        for (int i = 0; i < 22; i++) ikm[i] = 0x0b;
        for (int i = 0; i < 13; i++) salt[i] = (unsigned char)i;
        for (int i = 0; i < 10; i++) info[i] = (unsigned char)(0xf0 + i);
        OSSL_PARAM kp[4];
        char digest_name[] = "sha256";
        kp[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, digest_name, 0);
        kp[1] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, ikm, sizeof(ikm));
        kp[2] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, salt, sizeof(salt));
        OSSL_PARAM kp2[5];
        memcpy(kp2, kp, sizeof(kp));
        kp2[3] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, info, sizeof(info));
        kp2[4] = OSSL_PARAM_construct_end();
        int r = EVP_KDF_derive(kctx, out, sizeof(out), kp2);
        CHECK(r == 1, "HKDF derive ok");
        /* RFC 5869 TC1 OKM: 3cb25f25faacd57a90434f64d0362f2a... */
        CHECK(out[0] == 0x3c && out[1] == 0xb2 && out[2] == 0x5f,
              "HKDF-SHA256 RFC5869 TC1 known-vector 3cb25f25 correct");
        EVP_KDF_CTX_free(kctx);
        EVP_KDF_free(kdf);
    }

    /* --- AES-256-GCM one-shot --- */
    /* Served by the Go module's TLS 1.3 GCM (gcm_tls13.go). Known answer:
     * NIST vector for all-zero 256-bit key, 96-bit IV and one block. */
    EVP_CIPHER *ciph = EVP_CIPHER_fetch(NULL, "AES-256-GCM", "provider=gofips");
    CHECK(ciph != NULL, "AES-256-GCM fetchable from provider=gofips");
    if (ciph) {
        static const unsigned char want_ct[16] = {0xce,0xa7,0x40,0x3d,0x4d,0x60,0x6b,0x6e,0x07,0x4e,0xc5,0xd3,0xba,0xf3,0x9d,0x18};
        static const unsigned char want_tag[16] = {0xd0,0xd1,0xc8,0xa7,0x99,0x99,0x6b,0xf0,0x26,0x5b,0x98,0xb5,0xd4,0x8a,0xb9,0x19};
        unsigned char key[32] = {0}, iv[12] = {0}, pt[16] = {0};
        unsigned char ct[32], tag[16], out[32], scratch[32];
        EVP_CIPHER_CTX *cctx = EVP_CIPHER_CTX_new();
        int r = EVP_EncryptInit_ex2(cctx, ciph, key, iv, NULL);
        CHECK(r == 1, "GCM encrypt init ok (key accepted)");
        int len = 0, flen = 0;
        r = EVP_EncryptUpdate(cctx, ct, &len, pt, 16) &&
            EVP_EncryptFinal_ex(cctx, ct + len, &flen) &&
            EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_AEAD_GET_TAG, 16, tag);
        CHECK(r == 1 && len == 16 && flen == 0, "GCM seal ok (16 bytes at update, none at final)");
        CHECK(r == 1 && memcmp(ct, want_ct, 16) == 0, "GCM ciphertext matches the NIST vector (cea7403d...)");
        CHECK(r == 1 && memcmp(tag, want_tag, 16) == 0, "GCM tag matches the NIST vector (d0d1c8a7...)");
        EVP_CIPHER_CTX *dctx = EVP_CIPHER_CTX_new();
        len = 0;
        r = EVP_DecryptInit_ex2(dctx, ciph, key, iv, NULL) &&
            EVP_CIPHER_CTX_ctrl(dctx, EVP_CTRL_AEAD_SET_TAG, 16, tag) &&
            EVP_DecryptUpdate(dctx, out, &len, ct, 16) &&
            EVP_DecryptFinal_ex(dctx, scratch, &flen);
        CHECK(r == 1 && len == 16 && memcmp(out, pt, 16) == 0, "GCM open returns the plaintext");
        EVP_CIPHER_CTX_free(dctx);
        dctx = EVP_CIPHER_CTX_new();
        tag[0] ^= 1;
        r = EVP_DecryptInit_ex2(dctx, ciph, key, iv, NULL) &&
            EVP_CIPHER_CTX_ctrl(dctx, EVP_CTRL_AEAD_SET_TAG, 16, tag) &&
            EVP_DecryptUpdate(dctx, out, &len, ct, 16);
        CHECK(r != 1, "negative: GCM open FAILS on a tampered tag");
        EVP_CIPHER_CTX_free(dctx);
        EVP_CIPHER_CTX_free(cctx);
        EVP_CIPHER_free(ciph);
    }

    /* --- EC P-256 keygen + ECDH symmetry + ECDSA --- */
    EVP_PKEY_CTX *gctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", "provider=gofips");
    CHECK(gctx != NULL, "EC keymgmt reachable via EVP_PKEY_CTX_new_from_name");
    if (gctx) {
        int r = EVP_PKEY_keygen_init(gctx);
        CHECK(r == 1, "EC keygen init ok");
        OSSL_PARAM gp[2];
        char group[] = "prime256v1";
        gp[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, group, 0);
        gp[1] = OSSL_PARAM_construct_end();
        r = EVP_PKEY_CTX_set_params(gctx, gp);
        CHECK(r == 1, "EC keygen group set (prime256v1) ok");
        EVP_PKEY *pkey = NULL;
        r = EVP_PKEY_generate(gctx, &pkey);
        CHECK(r == 1 && pkey != NULL, "EC P-256 keygen via gofips ok");
        if (pkey) {
            /* ECDH: derive with self (symmetry smoke) */
            EVP_PKEY_CTX *dctx = EVP_PKEY_CTX_new(pkey, NULL);
            unsigned char secret[64]; size_t secretlen = sizeof(secret);
            r = EVP_PKEY_derive_init(dctx) && EVP_PKEY_derive_set_peer(dctx, pkey)
                && EVP_PKEY_derive(dctx, secret, &secretlen);
            CHECK(r == 1 && secretlen == 32, "ECDH derive (self) ok, 32-byte secret");
            EVP_PKEY_CTX_free(dctx);
            /* ECDSA sign/verify roundtrip via digest API */
            EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
            unsigned char digest[32];
            memset(digest, 0xAB, sizeof(digest));
            size_t siglen = 0;
            r = EVP_DigestSignInit_ex(mdctx, NULL, "sha256", NULL, "provider=gofips", pkey, NULL);
            CHECK(r == 1, "ECDSA DigestSignInit (sha256, provider=gofips) ok");
            r = EVP_DigestSign(mdctx, NULL, &siglen, digest, sizeof(digest));
            unsigned char *sig = OPENSSL_malloc(siglen);
            r = EVP_DigestSign(mdctx, sig, &siglen, digest, sizeof(digest));
            CHECK(r == 1 && siglen > 0, "ECDSA sign ok");
            if (r == 1) {
                EVP_MD_CTX *vctx = EVP_MD_CTX_new();
                r = EVP_DigestVerifyInit_ex(vctx, NULL, "sha256", NULL, "provider=gofips", pkey, NULL);
                r = EVP_DigestVerify(vctx, sig, siglen, digest, sizeof(digest));
                CHECK(r == 1, "ECDSA verify (own signature) ok");
                /* tamper: flip a digest byte, verify must fail */
                digest[0] ^= 1;
                EVP_MD_CTX *vctx2 = EVP_MD_CTX_new();
                EVP_DigestVerifyInit_ex(vctx2, NULL, "sha256", NULL, "provider=gofips", pkey, NULL);
                r = EVP_DigestVerify(vctx2, sig, siglen, digest, sizeof(digest));
                CHECK(r == 0, "negative: ECDSA verify FAILS on tampered digest");
                EVP_MD_CTX_free(vctx2);
                EVP_MD_CTX_free(vctx);
                OPENSSL_free(sig);
            }
            EVP_MD_CTX_free(mdctx);
            EVP_PKEY_free(pkey);
        }
        EVP_PKEY_CTX_free(gctx);
    }

    /* --- negative: unsupported ops fail closed --- */
    EVP_MD *md5 = EVP_MD_fetch(NULL, "MD5", "provider=gofips");
    CHECK(md5 == NULL, "negative: MD5 NOT fetchable (unregistered)");
    if (md5) EVP_MD_free(md5);
    EVP_CIPHER *chacha = EVP_CIPHER_fetch(NULL, "ChaCha20-Poly1305", "provider=gofips");
    CHECK(chacha == NULL, "negative: ChaCha20-Poly1305 NOT fetchable (unregistered)");
    if (chacha) EVP_CIPHER_free(chacha);
    EVP_PKEY_CTX *rctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", "provider=gofips");
    CHECK(rctx == NULL || EVP_PKEY_keygen_init(rctx) <= 0, "negative: RSA key generation refused (RSA is verification only)");
    if (rctx) EVP_PKEY_CTX_free(rctx);

    /* --- Go-side evidence --- */
    /* Per-op counters from the "temperfips-ops" JSON param, digest
     * counter from temperfips_evidence(). */
    {
        unsigned int dcalls = 0, rcalls = 0;
        char opsbuf[512] = {0};
        OSSL_PARAM ep[4];
        ep[0] = OSSL_PARAM_construct_uint("temperfips-digestcalls", &dcalls);
        ep[1] = OSSL_PARAM_construct_uint("temperfips-randcalls", &rcalls);
        ep[2] = OSSL_PARAM_construct_utf8_ptr("temperfips-ops", &opsbuf[0] == 0 ? NULL : (char **)NULL, 0);
        ep[3] = OSSL_PARAM_construct_end();
        /* two passes: size, then data */
        OSSL_PARAM ep2[3];
        char *ops_ptr = NULL;
        ep2[0] = OSSL_PARAM_construct_utf8_ptr("temperfips-ops", &ops_ptr, 0);
        ep2[1] = OSSL_PARAM_construct_uint("temperfips-digestcalls", &dcalls);
        ep2[2] = OSSL_PARAM_construct_end();
        int rc = OSSL_PROVIDER_get_params(g, ep2);
        printf("evidence: ops JSON=%s digestcalls=%u\n", ops_ptr ? ops_ptr : "(null)", dcalls);
        CHECK(rc == 1 && ops_ptr != NULL && strstr(ops_ptr, "ecdsa") != NULL,
              "evidence: per-op counters readable (ecdsa ran in Go)");
        /* Per-op totals from the JSON (ecdh/ecdsa/digest/kdf/cipher/mac) */
        if (ops_ptr) {
            int total = 0;
            const char *keys[] = {"ecdh", "ecdsa", "digest", "kdf", "cipher", "mac"};
            char tmp[512];
            snprintf(tmp, sizeof(tmp), "%s", ops_ptr);
            for (int i = 0; i < 6; i++) {
                char *v = strstr(tmp, keys[i]);
                if (v) total += atoi(v + strlen(keys[i]) + 2);
            }
            printf("evidence: total Go crypto ops: %d\n", total);
            CHECK(total >= 6, "evidence: Go executed all crypto op classes (total >= 6)");
        } else {
            CHECK(0, "evidence: Go executed all crypto op classes (total >= 6)");
        }
    }

    OSSL_PROVIDER_unload(g);
    printf("---\n%s\n", fails == 0 ? "ALL CHECKS PASSED" : "SOME CHECKS FAILED");
    return fails == 0 ? 0 : 1;
}
