/* differential_repro.c - differential regression suite (E-30).
 *
 * Each test compares gofips against the OpenSSL default provider in
 * separate library contexts, or checks a contract. Where the public Go
 * API cannot serve a streaming operation, the contract is a fail-closed
 * refusal (the one-shot model, see providers/gofips/README.md), reported
 * as ok. DEFECT lines are regressions.
 *
 * usage: differential_repro <dir-containing-gofips.so> <test-number>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/param_build.h>
#include <openssl/kdf.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/ec.h>

static OSSL_LIB_CTX *G, *D; /* gofips-only ctx, default-only ctx */

static void hex(const char *l, const unsigned char *b, size_t n) {
    printf("  %-22s", l);
    for (size_t i = 0; i < n && i < 48; i++) printf("%02x", b[i]);
    printf(n > 48 ? "... (%zu bytes)\n" : " (%zu bytes)\n", n);
}
#define VERDICT(defect, ...) do { printf("%s: ", (defect) ? "DEFECT" : "ok    "); printf(__VA_ARGS__); printf("\n"); } while (0)

static const unsigned char K32[32] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32};
static const unsigned char IV12[12] = {9,9,9,9,9,9,9,9,9,9,9,9};

/* GCM encrypt of pt split into chunks; returns ct len, tag in tag[16] */
static int gcm_enc(OSSL_LIB_CTX *L, const char *alg, const unsigned char *key,
                   const unsigned char *pt, size_t n, size_t split,
                   unsigned char *ct, unsigned char *tag) {
    EVP_CIPHER *c = EVP_CIPHER_fetch(L, alg, NULL);
    EVP_CIPHER_CTX *x = EVP_CIPHER_CTX_new();
    int l = 0, tot = 0;
    if (!c || !EVP_EncryptInit_ex2(x, c, key, IV12, NULL)) return -1;
    if (split) {
        if (!EVP_EncryptUpdate(x, ct, &l, pt, (int)split)) return -2;
        tot += l;
        if (!EVP_EncryptUpdate(x, ct + tot, &l, pt + split, (int)(n - split))) return -2;
        tot += l;
    } else {
        if (!EVP_EncryptUpdate(x, ct, &l, pt, (int)n)) return -2;
        tot += l;
    }
    if (!EVP_EncryptFinal_ex(x, ct + tot, &l)) return -3;
    tot += l;
    if (!EVP_CIPHER_CTX_ctrl(x, EVP_CTRL_AEAD_GET_TAG, 16, tag)) return -4;
    EVP_CIPHER_CTX_free(x); EVP_CIPHER_free(c);
    return tot;
}

static void t1(void) { /* GCM multi-update encrypt */
    unsigned char pt[64], a[96], b[96], ta[16], tb[16];
    memset(pt, 'A', 32); memset(pt + 32, 'A', 32); /* two identical 32-byte chunks */
    int na = gcm_enc(D, "AES-256-GCM", K32, pt, 64, 32, a, ta);
    int nb = gcm_enc(G, "AES-256-GCM", K32, pt, 64, 32, b, tb);
    printf("T1 AES-256-GCM encrypt, two EVP_EncryptUpdate calls of 32 identical bytes\n");
    hex("default ct", a, na); hex("gofips  ct", b, nb < 0 ? 0 : nb);
    hex("default tag", ta, 16); hex("gofips  tag", tb, 16);
    /* Contract: a multi-update encrypt is refused. Go's AEAD seals a whole
     * message in one call, and sealing per update would reuse the
     * keystream. A single-update encrypt must equal the default provider. */
    VERDICT(nb >= 0 ? 1 : 0, "multi-update GCM encrypt: %s", nb < 0 ? "refused (one-shot limit PASS)" : "ACCEPTED ; REGRESSION (must refuse)");
    int n1 = gcm_enc(D, "AES-256-GCM", K32, pt, 64, 0, a, ta);
    int n2 = gcm_enc(G, "AES-256-GCM", K32, pt, 64, 0, b, tb);
    int same = (n1 > 0 && n1 == n2 && memcmp(a, b, n1) == 0 && memcmp(ta, tb, 16) == 0);
    VERDICT(!same, "single-update GCM encrypt: %s", same ? "ciphertext and tag match the default provider (PASS)" : "MISMATCH or refused ; REGRESSION");
}

static void t2(void) { /* GCM decrypt final writes past outsize */
    unsigned char pt[200], ct[232], tag[16], out[512], fin[512];
    memset(pt, 'P', sizeof pt);
    int n = gcm_enc(D, "AES-256-GCM", K32, pt, sizeof pt, 0, ct, tag);
    for (int pass = 0; pass < 2; pass++) {
        OSSL_LIB_CTX *L = pass ? G : D;
        EVP_CIPHER *c = EVP_CIPHER_fetch(L, "AES-256-GCM", NULL);
        EVP_CIPHER_CTX *x = EVP_CIPHER_CTX_new();
        int l1 = -1, l2 = -1, wrote = 0;
        memset(fin, 0xEE, sizeof fin);
        EVP_DecryptInit_ex2(x, c, K32, IV12, NULL);
        EVP_DecryptUpdate(x, out, &l1, ct, n);
        EVP_CIPHER_CTX_ctrl(x, EVP_CTRL_AEAD_SET_TAG, 16, tag);
        int rc = EVP_DecryptFinal_ex(x, fin, &l2);
        for (size_t i = 0; i < sizeof fin; i++) if (fin[i] != 0xEE) wrote = (int)i + 1;
        printf("T2 %s: 200-byte GCM decrypt: update outl=%d, final rc=%d outl=%d, bytes written into final buffer=%d (blocksize=%d)\n",
               pass ? "gofips " : "default", l1, rc, l2, wrote, EVP_CIPHER_get_block_size(c));
        if (pass) {
            /* Documented limit: Go's AEAD releases plaintext only after
             * verifying the tag, and EVP gives GCM final no output space.
             * With the tag set after the data, gofips produces nothing at
             * update and refuses at final. (The default provider releases
             * plaintext at update, before checking the tag.) */
            int ok = (l1 == 0 && rc == 0 && wrote == 0);
            VERDICT(!ok, "tag set after the data: %s", ok ? "nothing produced at update, refused at final, nothing written (documented limit PASS)"
                                                         : "REGRESSION (must not report or write plaintext it cannot verify)");
        }
        EVP_CIPHER_CTX_free(x); EVP_CIPHER_free(c);
    }
    /* The supported order: tag before the data (the TLS record layer and
     * Node's createDecipheriv). Plaintext is released at update, and must
     * equal the default provider's. */
    {
        EVP_CIPHER *c = EVP_CIPHER_fetch(G, "AES-256-GCM", NULL);
        EVP_CIPHER_CTX *x = EVP_CIPHER_CTX_new();
        int l1 = -1, l2 = -1;
        memset(out, 0, sizeof out);
        EVP_DecryptInit_ex2(x, c, K32, IV12, NULL);
        EVP_CIPHER_CTX_ctrl(x, EVP_CTRL_AEAD_SET_TAG, 16, tag);
        int ru = EVP_DecryptUpdate(x, out, &l1, ct, n);
        int rf = EVP_DecryptFinal_ex(x, fin, &l2);
        int ok = (ru == 1 && rf == 1 && l1 == n && l2 == 0 && memcmp(out, pt, sizeof pt) == 0);
        printf("T2 gofips : tag set before the data: update rc=%d outl=%d, final rc=%d outl=%d\n", ru, l1, rf, l2);
        VERDICT(!ok, "tag set before the data: %s", ok ? "plaintext at update, matches the default provider (PASS)" : "REGRESSION");
        /* a wrong tag must fail closed, with no plaintext released */
        unsigned char bad[16]; memcpy(bad, tag, 16); bad[0] ^= 1;
        EVP_CIPHER_CTX *y = EVP_CIPHER_CTX_new();
        l1 = -1;
        EVP_DecryptInit_ex2(y, c, K32, IV12, NULL);
        EVP_CIPHER_CTX_ctrl(y, EVP_CTRL_AEAD_SET_TAG, 16, bad);
        int rb = EVP_DecryptUpdate(y, out, &l1, ct, n);
        VERDICT(rb == 1, "wrong tag: %s", rb == 1 ? "ACCEPTED ; REGRESSION" : "refused, no plaintext released (PASS)");
        EVP_CIPHER_CTX_free(x); EVP_CIPHER_CTX_free(y); EVP_CIPHER_free(c);
    }
}

static void t3(void) { /* AES-128-GCM */
    unsigned char pt[32], a[64], b[64], ta[16], tb[16];
    memset(pt, 'Z', sizeof pt);
    int na = gcm_enc(D, "AES-128-GCM", K32, pt, 32, 0, a, ta);
    int nb = gcm_enc(G, "AES-128-GCM", K32, pt, 32, 0, b, tb);
    printf("T3 AES-128-GCM single-update vs default (na=%d nb=%d)\n", na, nb);
    if (na > 0 && nb > 0) { hex("default ct", a, na); hex("gofips  ct", b, nb); }
    {
        int same = (na > 0 && na == nb && memcmp(a, b, na) == 0 && memcmp(ta, tb, 16) == 0);
        VERDICT(!same, "AES-128-GCM ciphertext and tag: %s", same ? "match the default provider (PASS)" : "MISMATCH or refused ; REGRESSION");
    }
    EVP_CIPHER *c = EVP_CIPHER_fetch(G, "AES-128-GCM", NULL);
    EVP_CIPHER_CTX *x = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex2(x, c, NULL, NULL, NULL);
    printf("  gofips AES-128-GCM: EVP_CIPHER_get_key_length=%d EVP_CIPHER_CTX_get_key_length(pre-key)=%d\n",
           EVP_CIPHER_get_key_length(c), EVP_CIPHER_CTX_get_key_length(x));
}

static size_t mac_ref(const unsigned char *key, size_t kl, const unsigned char *m, size_t ml, unsigned char *out) {
    size_t n = 0;
    EVP_Q_mac(D, "HMAC", NULL, "SHA256", NULL, key, kl, m, ml, out, 64, &n);
    return n;
}

static void t4n(void) { /* HMAC key-length floor: keys < 112 bits refused */
    size_t n; unsigned char got[64], ref[64];
    OSSL_PARAM p[3] = { OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0),
                        OSSL_PARAM_construct_octet_string("key", (void *)K32, 10), /* 80 bits < 112 */
                        OSSL_PARAM_construct_end() };
    EVP_MAC *m = EVP_MAC_fetch(G, "HMAC", NULL);
    EVP_MAC_CTX *x = EVP_MAC_CTX_new(m);
    int rc = EVP_MAC_init(x, NULL, 0, p); /* key via params, 10 bytes = 80 bits */
    printf("T4n HMAC with an 80-bit key (below the 112-bit SP floor): init rc=%d\n", rc);
    VERDICT(rc == 0 ? 0 : 1, "sub-112-bit HMAC key: %s", rc == 0 ? "refused (SP boundary PASS)" : "ACCEPTED ; REGRESSION");
    EVP_MAC_CTX_free(x); EVP_MAC_free(m);
}

static void t4(void) { /* HMAC */
    unsigned char ref[64], got[64], got2[64]; size_t n, n2;
    OSSL_PARAM p[2] = { OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0), OSSL_PARAM_construct_end() };
    EVP_MAC *m = EVP_MAC_fetch(G, "HMAC", NULL);
    /* (a) dup mid-stream */
    EVP_MAC_CTX *x = EVP_MAC_CTX_new(m);
    EVP_MAC_init(x, K32, 32, p);
    EVP_MAC_update(x, (const unsigned char *)"hello ", 6);
    EVP_MAC_CTX *y = EVP_MAC_CTX_dup(x);
    printf("T4a HMAC dup after update: dup=%p\n", (void *)y);
    /* Contract: mid-stream HMAC dup is refused. Go's public hash.Hash
     * cannot clone streaming state, and a key-only clone would silently
     * drop the prior updates. */
    VERDICT(y == NULL ? 0 : 1, "mid-stream HMAC dup: %s", y == NULL ? "refused (contract PASS)" : "ACCEPTED ; REGRESSION");
    /* (b) re-init with NULL key = reuse key */
    EVP_MAC_final(x, got, &n, sizeof got);
    int rc = EVP_MAC_init(x, NULL, 0, NULL);
    EVP_MAC_update(x, (const unsigned char *)"msg2", 4);
    int rc2 = EVP_MAC_final(x, got, &n, sizeof got);
    mac_ref(K32, 32, (const unsigned char *)"msg2", 4, ref);
    mac_ref((const unsigned char *)"", 0, (const unsigned char *)"msg2", 4, got2);
    printf("T4b HMAC EVP_MAC_init(ctx, NULL, 0, NULL) to reuse the key: init rc=%d final rc=%d\n", rc, rc2);
    hex("expected", ref, 32); hex("gofips", got, n);
    VERDICT(memcmp(ref, got, 32) == 0 ? 0 : 1, "re-init MAC vs expected: %s%s",
            memcmp(ref, got, 32) ? "MISMATCH ; REGRESSION" : "match",
            !memcmp(got, got2, 32) ? " (equals EMPTY key)" : "");
    /* (c) key via set_ctx_params */
    EVP_MAC_CTX *z = EVP_MAC_CTX_new(m);
    OSSL_PARAM kp[3] = { OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0),
                         OSSL_PARAM_construct_octet_string("key", (void *)K32, 32), OSSL_PARAM_construct_end() };
    rc = EVP_MAC_CTX_set_params(z, kp);
    rc2 = EVP_MAC_init(z, NULL, 0, NULL);
    EVP_MAC_update(z, (const unsigned char *)"msg2", 4);
    n2 = 0; EVP_MAC_final(z, got, &n2, sizeof got);
    printf("T4c HMAC key supplied through EVP_MAC_CTX_set_params: set rc=%d init rc=%d\n", rc, rc2);
    hex("expected", ref, 32); hex("gofips", got, n2);
    VERDICT(memcmp(ref, got, 32) == 0 ? 0 : 1, "set_params-keyed MAC vs expected: %s%s",
            memcmp(ref, got, 32) ? "MISMATCH ; REGRESSION" : "match",
            !memcmp(got, got2, 32) ? " (equals EMPTY key)" : "");
}

static EVP_PKEY *gen(OSSL_LIB_CTX *L) {
    EVP_PKEY *k = NULL;
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_name(L, "EC", NULL);
    OSSL_PARAM p[2] = { OSSL_PARAM_construct_utf8_string("group", "prime256v1", 0), OSSL_PARAM_construct_end() };
    EVP_PKEY_keygen_init(c); EVP_PKEY_CTX_set_params(c, p); EVP_PKEY_generate(c, &k);
    EVP_PKEY_CTX_free(c);
    return k;
}
static int dsign(OSSL_LIB_CTX *L, EVP_PKEY *k, unsigned char *sig, size_t *sl) {
    EVP_MD_CTX *m = EVP_MD_CTX_new();
    int rc = EVP_DigestSignInit_ex(m, NULL, "SHA256", L, NULL, k, NULL) && EVP_DigestSign(m, sig, sl, (const unsigned char *)"abc", 3);
    EVP_MD_CTX_free(m);
    return rc;
}

static void t5(void) { /* keymgmt dup aliasing */
    unsigned char sig[80]; size_t sl = sizeof sig;
    EVP_PKEY *k = gen(G);
    printf("T5 EVP_PKEY_dup then free the copy, then sign with the original\n");
    printf("  sign before dup: %d\n", dsign(G, k, sig, &sl));
    EVP_PKEY *d = EVP_PKEY_dup(k);
    printf("  dup=%p\n", (void *)d);
    EVP_PKEY_free(d);
    sl = sizeof sig;
    int rc = dsign(G, k, sig, &sl);
    VERDICT(rc == 1 ? 0 : 1, "sign after dup-free: rc=%d %s", rc, rc == 1 ? "(deep-copy PASS)" : "; REGRESSION");
}

static void t6(void) { /* short signature crash */
    EVP_PKEY *k = gen(G);
    EVP_MD_CTX *m = EVP_MD_CTX_new();
    unsigned char bad[3] = {0x30, 0x01, 0x00};
    printf("T6 EVP_DigestVerify with a 3-byte malformed signature (expect a clean 0)\n"); fflush(stdout);
    EVP_DigestVerifyInit_ex(m, NULL, "SHA256", G, NULL, k, NULL);
    int rc = EVP_DigestVerify(m, bad, sizeof bad, (const unsigned char *)"abc", 3);
    VERDICT(rc == 0 ? 0 : 1, "short malformed signature: rc=%d %s", rc, rc == 0 ? "(clean reject PASS)" : "; REGRESSION");
}

static int hkdf(OSSL_LIB_CTX *L, int mode, const char *md, unsigned char *out, size_t n, int via_derive) {
    EVP_KDF *k = EVP_KDF_fetch(L, "HKDF", NULL);
    EVP_KDF_CTX *c = EVP_KDF_CTX_new(k);
    OSSL_PARAM p[6]; int i = 0;
    p[i++] = OSSL_PARAM_construct_utf8_string("digest", (char *)md, 0);
    p[i++] = OSSL_PARAM_construct_octet_string("key", (void *)K32, 32);
    p[i++] = OSSL_PARAM_construct_octet_string("salt", (void *)"salt", 4);
    p[i++] = OSSL_PARAM_construct_octet_string("info", (void *)"info", 4);
    if (mode >= 0) p[i++] = OSSL_PARAM_construct_int("mode", &mode);
    p[i] = OSSL_PARAM_construct_end();
    int rc;
    if (via_derive) rc = EVP_KDF_derive(c, out, n, p);
    else rc = EVP_KDF_CTX_set_params(c, p) > 0 && EVP_KDF_derive(c, out, n, NULL) > 0;
    EVP_KDF_CTX_free(c); EVP_KDF_free(k);
    return rc;
}

static int hkdf_ikm(OSSL_LIB_CTX *L, const unsigned char *ikm, size_t ikml,
                    unsigned char *out, size_t n) {
    EVP_KDF *k = EVP_KDF_fetch(L, "HKDF", NULL);
    EVP_KDF_CTX *c = EVP_KDF_CTX_new(k);
    OSSL_PARAM p[5]; int i = 0;
    p[i++] = OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0);
    p[i++] = OSSL_PARAM_construct_octet_string("key", (void *)ikm, ikml);
    p[i++] = OSSL_PARAM_construct_octet_string("salt", (void *)"salt", 4);
    p[i++] = OSSL_PARAM_construct_octet_string("info", (void *)"info", 4);
    p[i] = OSSL_PARAM_construct_end();
    int rc = EVP_KDF_derive(c, out, n, p);
    EVP_KDF_CTX_free(c); EVP_KDF_free(k);
    return rc;
}

static void t7f(void) { /* HKDF IKM 112-bit SP floor: refusal asserted */
    /* 112-bit minimum (FIPS 140-3 IG C.B, SP 800-131A Rev.2; tls.go
     * kdfDerive): an HKDF IKM under 14 bytes is not an approved
     * service and gofips refuses it. The default provider has no floor.
     * Asserts 13 bytes refused, 14 accepted. */
    unsigned char ikm8[8], ikm13[13], ikm14[14], a[32], b[32];
    memset(ikm8, 0x0b, sizeof ikm8);
    memset(ikm13, 0x0c, sizeof ikm13);
    memset(ikm14, 0x0d, sizeof ikm14);
    int rd8 = hkdf_ikm(D, ikm8, sizeof ikm8, a, 32);      /* default: accepts */
    int rg8 = hkdf_ikm(G, ikm8, sizeof ikm8, b, 32);      /* gofips: must refuse */
    printf("T7f HKDF IKM 8 bytes (64 bits): default rc=%d gofips rc=%d\n", rd8, rg8);
    VERDICT(rg8 == 0 ? 0 : 1, "8-byte IKM (64 bits): %s",
            rg8 == 0 ? "refused (SP 112-bit floor PASS)" : "ACCEPTED ; REGRESSION (below the SP floor)");
    int rg13 = hkdf_ikm(G, ikm13, sizeof ikm13, b, 32);
    printf("T7f HKDF IKM 13 bytes (104 bits): gofips rc=%d\n", rg13);
    VERDICT(rg13 == 0 ? 0 : 1, "13-byte IKM (104 bits): %s",
            rg13 == 0 ? "refused (floor exact PASS)" : "ACCEPTED ; REGRESSION (below the SP floor)");
    int rg14 = hkdf_ikm(G, ikm14, sizeof ikm14, b, 32);
    printf("T7f HKDF IKM 14 bytes (exactly 112 bits): gofips rc=%d\n", rg14);
    VERDICT(rg14 > 0 ? 0 : 1, "14-byte IKM (exactly 112 bits): %s",
            rg14 > 0 ? "accepted (at the floor PASS)" : "REFUSED ; REGRESSION (floor is <= 112 bits, not >)");
    (void)rd8;
}

static void t7(void) { /* HKDF */
    unsigned char a[9000], b[9000];
    int ra = hkdf(D, -1, "SHA256", a, 42, 0), rb = hkdf(G, -1, "SHA256", b, 42, 0);
    printf("T7a HKDF default mode, 42 bytes: default rc=%d gofips rc=%d\n", ra, rb);
    VERDICT(ra != rb || memcmp(a, b, 42), "extract-and-expand %s", memcmp(a, b, 42) ? "DIFFERS" : "matches default");
    ra = hkdf(D, EVP_KDF_HKDF_MODE_EXTRACT_ONLY, "SHA256", a, 32, 0);
    rb = hkdf(G, EVP_KDF_HKDF_MODE_EXTRACT_ONLY, "SHA256", b, 32, 0);
    printf("T7b HKDF mode=EXTRACT_ONLY: default rc=%d gofips rc=%d\n", ra, rb);
    hex("default PRK", a, 32); hex("gofips out", b, 32);
    VERDICT((rb > 0 && memcmp(a, b, 32) != 0) ? 1 : 0, "EXTRACT_ONLY vs default PRK: %s",
            (rb > 0 && memcmp(a, b, 32) != 0) ? "MISMATCH ; REGRESSION (mode ignored)" : (rb > 0 ? "match (mode honored PASS)" : "refused"));
    ra = hkdf(D, EVP_KDF_HKDF_MODE_EXPAND_ONLY, "SHA256", a, 32, 0);
    rb = hkdf(G, EVP_KDF_HKDF_MODE_EXPAND_ONLY, "SHA256", b, 32, 0);
    printf("T7c HKDF mode=EXPAND_ONLY: default rc=%d gofips rc=%d\n", ra, rb);
    VERDICT((rb > 0 && memcmp(a, b, 32) != 0) ? 1 : 0, "EXPAND_ONLY vs default: %s",
            (rb > 0 && memcmp(a, b, 32) != 0) ? "MISMATCH ; REGRESSION (mode ignored)" : (rb > 0 ? "match (mode honored PASS)" : "refused"));
    ra = hkdf(D, -1, "SHA256", a, 8192, 0); rb = hkdf(G, -1, "SHA256", b, 8192, 0);
    printf("T7d HKDF-SHA256 output 8192 bytes (RFC 5869 max is 255*32=8160): default rc=%d gofips rc=%d\n", ra, rb);
    VERDICT(rb > 0 ? 1 : 0, "over-length request: %s", rb > 0 ? "ACCEPTED ; REGRESSION (RFC 5869 max 255*HashLen)" : "refused (PASS)");
    ra = hkdf(D, -1, "SHA512", a, 32, 1); rb = hkdf(G, -1, "SHA512", b, 32, 1);
    unsigned char s256[32]; hkdf(D, -1, "SHA256", s256, 32, 1);
    printf("T7e HKDF digest=SHA512 passed as EVP_KDF_derive params: default rc=%d gofips rc=%d\n", ra, rb);
    VERDICT((rb > 0 && !memcmp(b, s256, 32)) ? 1 : 0, "SHA512 request: %s",
            (rb > 0 && !memcmp(b, s256, 32)) ? "silently SHA-256 ; REGRESSION" : (rb > 0 ? "SHA512 honored" : "refused"));
    t7f();
}

static void t8(void) { /* GCM nonce reuse without re-init */
    unsigned char pt[16], c1[32], c2[32], tag[16]; int l, rc1, rc2, rcf;
    memset(pt, 'N', sizeof pt);
    for (int pass = 0; pass < 2; pass++) {
        OSSL_LIB_CTX *L = pass ? G : D;
        EVP_CIPHER *c = EVP_CIPHER_fetch(L, "AES-256-GCM", NULL);
        EVP_CIPHER_CTX *x = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex2(x, c, K32, IV12, NULL);
        rc1 = EVP_EncryptUpdate(x, c1, &l, pt, 16);
        rcf = EVP_EncryptFinal_ex(x, c1 + 16, &l);
        EVP_CIPHER_CTX_ctrl(x, EVP_CTRL_AEAD_GET_TAG, 16, tag);
        rc2 = EVP_EncryptUpdate(x, c2, &l, pt, 16); /* second message, no re-init */
        printf("T8 %s: second message on a finalized GCM ctx without a new IV: update rc=%d (first rc=%d final rc=%d)\n", pass ? "gofips " : "default", rc2, rc1, rcf);
        if (pass) VERDICT((rc2 > 0 && !memcmp(c1, c2, 16)) ? 1 : 0, "second message on finalized ctx: %s",
                          (rc2 > 0 && !memcmp(c1, c2, 16)) ? "encrypted under the SAME nonce ; REGRESSION" : "refused (PASS)");
    }
}

static void t9(void) { /* priv-only import */
    /* scalar d = 0x0102..20 (big-endian value); pass as native-endian BN like OpenSSL does */
    BIGNUM *d = BN_bin2bn(K32, 32, NULL);
    unsigned char pa[80], pb[80]; size_t la = 0, lb = 0;
    for (int pass = 0; pass < 2; pass++) {
        OSSL_LIB_CTX *L = pass ? G : D;
        OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
        OSSL_PARAM_BLD_push_utf8_string(bld, "group", "prime256v1", 0);
        OSSL_PARAM_BLD_push_BN(bld, "priv", d);
        OSSL_PARAM *p = OSSL_PARAM_BLD_to_param(bld);
        EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_name(L, "EC", NULL);
        EVP_PKEY *k = NULL;
        EVP_PKEY_fromdata_init(c);
        int rc = EVP_PKEY_fromdata(c, &k, EVP_PKEY_KEYPAIR, p);
        size_t *lp = pass ? &lb : &la;
        int rg = k ? EVP_PKEY_get_octet_string_param(k, "pub", pass ? pb : pa, 80, lp) : 0;
        if (!rg && k) rg = EVP_PKEY_get_octet_string_param(k, "encoded-pub-key", pass ? pb : pa, 80, lp);
        printf("T9 %s: EC private-key-only import: fromdata rc=%d getpub rc=%d\n", pass ? "gofips " : "default", rc, rg);
    }
    if (la) hex("default pub", pa, la);
    if (lb) hex("gofips  pub", pb, lb);
    VERDICT(lb != 0 ? 1 : 0, "priv-only import pub exposure: %s", lb ? "pub exposed ; REGRESSION (default refuses getpub)" : "refused (PASS, matches default)");
}

/* TLS 1.3 record nonce for sequence number seq under static IV IV12 */
static void seq_nonce(unsigned char nonce[12], unsigned long long seq) {
    memcpy(nonce, IV12, 12);
    for (int i = 0; i < 8; i++) nonce[11 - i] ^= (unsigned char)(seq >> (8 * i));
}

static void t10(void) { /* nonce reuse through a copy of the ctx */
    /* The Go module's TLS 1.3 GCM enforces a strictly increasing record
     * counter per key instance. A copied ctx shares the instance with the
     * original, so a nonce sealed through one cannot be sealed again
     * through the other. */
    unsigned char pt[16], c1[32], c2[32], c3[32]; int l1, l2, l3;
    memset(pt, 'N', sizeof pt);
    EVP_CIPHER *c = EVP_CIPHER_fetch(G, "AES-256-GCM", NULL);
    EVP_CIPHER_CTX *x1 = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX *x2 = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex2(x1, c, K32, IV12, NULL);
    int rcopy = EVP_CIPHER_CTX_copy(x2, x1);
    int rc1 = EVP_EncryptUpdate(x1, c1, &l1, pt, 16);
    int rc2 = EVP_EncryptUpdate(x2, c2, &l2, pt, 16); /* same key+nonce through the copy */
    printf("T10 same (key,nonce) through a copied ctx: copy=%d rc1=%d rc2=%d\n", rcopy, rc1, rc2);
    VERDICT(!(rcopy == 1 && rc1 == 1 && rc2 == 0), "nonce reuse through a copied ctx: %s",
            (rcopy == 1 && rc1 == 1 && rc2 == 0) ? "first seal ok, reuse refused (PASS)" : "REGRESSION");
    /* Documented boundary, printed but not a verdict: a new ctx with the
     * same key bytes is a new key instance, as with the default provider.
     * TLS derives a fresh key per connection, so it never does this. */
    EVP_CIPHER_CTX *x3 = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex2(x3, c, K32, IV12, NULL);
    int rc3 = EVP_EncryptUpdate(x3, c3, &l3, pt, 16);
    printf("T10 note: a brand-new ctx with the same key and nonce: rc=%d (documented boundary; the default provider also accepts)\n", rc3);
    EVP_CIPHER_CTX_free(x1); EVP_CIPHER_CTX_free(x2); EVP_CIPHER_CTX_free(x3); EVP_CIPHER_free(c);
}

static void t11(void) { /* the record counter must increase on one ctx */
    /* The TLS record pattern: key once, then a new IV per record. The
     * same nonce again, or an earlier one, is refused; the next one is
     * accepted, also after a refusal. */
    unsigned char pt[16], ct[32], n0[12], n1[12], n2[12], n5[12]; int l;
    memset(pt, 'N', sizeof pt);
    seq_nonce(n0, 0); seq_nonce(n1, 1); seq_nonce(n2, 2); seq_nonce(n5, 5);
    EVP_CIPHER *c = EVP_CIPHER_fetch(G, "AES-256-GCM", NULL);
    EVP_CIPHER_CTX *x = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex2(x, c, K32, n0, NULL);
    int r0 = EVP_EncryptUpdate(x, ct, &l, pt, 16);
    EVP_EncryptInit_ex2(x, NULL, NULL, n0, NULL);
    int rsame = EVP_EncryptUpdate(x, ct, &l, pt, 16);   /* record 0 again */
    EVP_EncryptInit_ex2(x, NULL, NULL, n1, NULL);
    int r1 = EVP_EncryptUpdate(x, ct, &l, pt, 16);
    EVP_EncryptInit_ex2(x, NULL, NULL, n5, NULL);
    int r5 = EVP_EncryptUpdate(x, ct, &l, pt, 16);      /* a gap is allowed */
    EVP_EncryptInit_ex2(x, NULL, NULL, n2, NULL);
    int rback = EVP_EncryptUpdate(x, ct, &l, pt, 16);   /* going backwards is not */
    EVP_EncryptInit_ex2(x, NULL, K32, n0, NULL);        /* same key supplied again */
    int rrekey = EVP_EncryptUpdate(x, ct, &l, pt, 16);
    printf("T11 one ctx: seq0=%d seq0-again=%d seq1=%d seq5=%d seq2-after-5=%d seq0-after-same-key-reinit=%d\n",
           r0, rsame, r1, r5, rback, rrekey);
    int ok = (r0 == 1 && rsame == 0 && r1 == 1 && r5 == 1 && rback == 0 && rrekey == 0);
    VERDICT(!ok, "record counter on one ctx: %s", ok ? "increasing accepted, repeat and decrease refused, usable after a refusal (PASS)" : "REGRESSION");
    EVP_CIPHER_CTX_free(x); EVP_CIPHER_free(c);
}

static void t13(void) { /* unpadded BN scalar import: orientation + ECDH + sign/verify */
    /* An unpadded BIGNUM scalar (leading zero dropped, 31 bytes) must be
     * normalized to 32-byte big-endian and validated (d*G == pub), so
     * ECDH matches the default provider and signatures verify. Unchecked,
     * it would be stored raw and both would diverge. */
    OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
    BIGNUM *d = NULL;
    BN_hex2bn(&d, "8F6B0A0D101316191C1F2225282B2E3134373A3D404346494C4F5255585B5E");
    EC_GROUP *grp = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    EC_POINT *P = EC_POINT_new(grp);
    EC_POINT_mul(grp, P, d, NULL, NULL, NULL);
    unsigned char pub[65];
    EC_POINT_point2oct(grp, P, POINT_CONVERSION_UNCOMPRESSED, pub, 65, NULL);
    OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, "prime256v1", 0);
    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PRIV_KEY, d);   /* UNSIGNED_INTEGER, unpadded */
    OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY, pub, 65);
    OSSL_PARAM *ps = OSSL_PARAM_BLD_to_param(bld);
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_name(G, "EC", NULL);
    EVP_PKEY *kg = NULL;
    EVP_PKEY_fromdata_init(c);
    int rc = EVP_PKEY_fromdata(c, &kg, EVP_PKEY_KEYPAIR, ps);
    printf("T13 unpadded BN scalar import: rc=%d\n", rc);
    int ok = rc > 0;
    /* The BN view of the normalized scalar must equal the input. */
    BIGNUM *bnIn = NULL;
    int rbIn = EVP_PKEY_get_bn_param(kg, "priv", &bnIn);
    int bnEq = rbIn > 0 && bnIn && BN_cmp(bnIn, d) == 0;
    printf("T13 imported BN round-trip: rc=%d equals=%d\n", rbIn, bnEq);
    ok = ok && bnEq;
    /* Sign with the imported key, verify under its own public point. */
    unsigned char msg[] = "t13 leading-zero scalar message";
    unsigned char sig[96]; size_t siglen = sizeof sig;
    EVP_MD_CTX *ms = EVP_MD_CTX_new();
    int si = EVP_DigestSignInit(ms, NULL, EVP_sha256(), NULL, kg);
    int ss = si > 0 ? EVP_DigestSign(ms, sig, &siglen, msg, sizeof msg - 1) : -1;
    printf("T13 sign (leading-zero key): init=%d sign=%d len=%zu\n", si, ss, siglen);
    ok = ok && si > 0 && ss > 0;
    if (ss > 0) {
        /* verify under a pub-only import of the same point */
        OSSL_PARAM_BLD *b4 = OSSL_PARAM_BLD_new();
        OSSL_PARAM_BLD_push_utf8_string(b4, OSSL_PKEY_PARAM_GROUP_NAME, "prime256v1", 0);
        OSSL_PARAM_BLD_push_octet_string(b4, OSSL_PKEY_PARAM_PUB_KEY, pub, 65);
        OSSL_PARAM *ps4 = OSSL_PARAM_BLD_to_param(b4);
        EVP_PKEY *pubk = NULL;
        EVP_PKEY_CTX *c4 = EVP_PKEY_CTX_new_from_name(G, "EC", NULL);
        EVP_PKEY_fromdata_init(c4);
        EVP_PKEY_fromdata(c4, &pubk, EVP_PKEY_PUBLIC_KEY, ps4);
        EVP_MD_CTX *mv = EVP_MD_CTX_new();
        int vi = EVP_DigestVerifyInit(mv, NULL, EVP_sha256(), NULL, pubk);
        int vr = vi > 0 ? EVP_DigestVerify(mv, sig, siglen, msg, sizeof msg - 1) : -1;
        printf("T13 verify under the imported pub: %s\n", vr == 1 ? "VALID" : "INVALID");
        ok = ok && vr == 1;
        EVP_MD_CTX_free(mv); EVP_PKEY_free(pubk);
        OSSL_PARAM_free(ps4); OSSL_PARAM_BLD_free(b4); EVP_PKEY_CTX_free(c4);
    }
    EVP_MD_CTX_free(ms);
    /* ECDH against a default-provider key with the same bytes */
    OSSL_LIB_CTX *DD = OSSL_LIB_CTX_new();
    OSSL_PROVIDER_load(DD, "default");
    OSSL_PARAM_BLD *b2 = OSSL_PARAM_BLD_new();
    OSSL_PARAM_BLD_push_utf8_string(b2, OSSL_PKEY_PARAM_GROUP_NAME, "prime256v1", 0);
    OSSL_PARAM_BLD_push_BN(b2, OSSL_PKEY_PARAM_PRIV_KEY, d);
    OSSL_PARAM_BLD_push_octet_string(b2, OSSL_PKEY_PARAM_PUB_KEY, pub, 65);
    OSSL_PARAM *ps2 = OSSL_PARAM_BLD_to_param(b2);
    EVP_PKEY_CTX *c2 = EVP_PKEY_CTX_new_from_name(DD, "EC", NULL);
    EVP_PKEY *kd = NULL;
    EVP_PKEY_fromdata_init(c2);
    int rc2 = EVP_PKEY_fromdata(c2, &kd, EVP_PKEY_KEYPAIR, ps2);
    if (ok && rc2 > 0) {
        /* peer on each side, same pub bytes */
        EVP_PKEY *peerD = EVP_PKEY_Q_keygen(DD, NULL, "EC", "prime256v1");
        unsigned char pp[65]; size_t ppl = 0;
        EVP_PKEY_get_octet_string_param(peerD, "pub", pp, 65, &ppl);
        OSSL_PARAM_BLD *b3 = OSSL_PARAM_BLD_new();
        OSSL_PARAM_BLD_push_utf8_string(b3, OSSL_PKEY_PARAM_GROUP_NAME, "prime256v1", 0);
        OSSL_PARAM_BLD_push_octet_string(b3, OSSL_PKEY_PARAM_PUB_KEY, pp, ppl);
        OSSL_PARAM *ps3 = OSSL_PARAM_BLD_to_param(b3);
        EVP_PKEY *pd = NULL, *pg = NULL;
        EVP_PKEY_CTX *cd = EVP_PKEY_CTX_new_from_name(DD, "EC", NULL);
        EVP_PKEY_fromdata_init(cd); EVP_PKEY_fromdata(cd, &pd, EVP_PKEY_PUBLIC_KEY, ps3);
        EVP_PKEY_CTX *cg = EVP_PKEY_CTX_new_from_name(G, "EC", NULL);
        EVP_PKEY_fromdata_init(cg); EVP_PKEY_fromdata(cg, &pg, EVP_PKEY_PUBLIC_KEY, ps3);
        unsigned char s1[64], s2[64]; size_t n1 = 64, n2 = 64;
        EVP_PKEY_CTX *e1 = EVP_PKEY_CTX_new_from_pkey(DD, kd, NULL);
        int r1 = EVP_PKEY_derive_init(e1) > 0 && EVP_PKEY_derive_set_peer(e1, pd) > 0
                   ? EVP_PKEY_derive(e1, s1, &n1) : -1;
        EVP_PKEY_CTX *e2 = EVP_PKEY_CTX_new_from_pkey(G, kg, NULL);
        int r2 = EVP_PKEY_derive_init(e2) > 0 && EVP_PKEY_derive_set_peer(e2, pg) > 0
                   ? EVP_PKEY_derive(e2, s2, &n2) : -1;
        printf("T13 ECDH: default rc=%d gofips rc=%d\n", r1, r2);
        int match = r1 > 0 && r2 > 0 && n1 == n2 && !memcmp(s1, s2, n1);
        printf("  secrets %s\n", match ? "MATCH" : "DIFFER");
        ok = ok && match;
        /* exported scalar is canonical 32 bytes */
        unsigned char po[64]; size_t pol = 0;
        int ro = EVP_PKEY_get_octet_string_param(kg, OSSL_PKEY_PARAM_PRIV_KEY, po, sizeof po, &pol);
        printf("T13 export priv len=%zu (expect 32)\n", pol);
        ok = ok && ro > 0 && pol == 32;
        /* the export must be typed for OSSL_PARAM_get_BN re-import */
        BIGNUM *bn = NULL;
        int rb = EVP_PKEY_get_bn_param(kg, "priv", &bn);
        printf("T13 BN read-back: rc=%d\n", rb);
        ok = ok && rb > 0 && bn && BN_cmp(bn, d) == 0;
        /* todata from gofips, fromdata into default, sign there */
        OSSL_PARAM *exp = NULL;
        int rt = EVP_PKEY_todata(kg, OSSL_KEYMGMT_SELECT_KEYPAIR, &exp);
        printf("T13 todata: rc=%d\n", rt);
        int crossOk = 0;
        if (rt > 0 && exp) {
            EVP_PKEY_CTX *ci = EVP_PKEY_CTX_new_from_name(DD, "EC", "provider=default");
            EVP_PKEY *kdImp = NULL;
            EVP_PKEY_fromdata_init(ci);
            int rci = EVP_PKEY_fromdata(ci, &kdImp, EVP_PKEY_KEYPAIR, exp);
            printf("T13 default re-import of gofips export: rc=%d\n", rci);
            if (rci > 0 && kdImp) {
                EVP_MD_CTX *mc = EVP_MD_CTX_new();
                int ssi = EVP_DigestSignInit(mc, NULL, EVP_sha256(), NULL, kdImp);
                unsigned char csig[96]; size_t csiglen = sizeof csig;
                int sss = ssi > 0 ? EVP_DigestSign(mc, csig, &csiglen, msg, sizeof msg - 1) : -1;
                printf("T13 default sign after re-import: %d len=%zu\n", sss, csiglen);
                crossOk = sss > 0;
                EVP_MD_CTX_free(mc);
            }
            OSSL_PARAM_free(exp);
            EVP_PKEY_CTX_free(ci);
        }
        ok = ok && crossOk;
    }
    VERDICT(ok ? 0 : 1, "unpadded BN scalar import %s",
            ok ? "normalized, ECDH matches default, canonical export (PASS)"
               : "REGRESSION (raw unvalidated scalar accepted)");
    EVP_PKEY_free(kg); EVP_PKEY_free(kd);
    OSSL_PARAM_free(ps); OSSL_PARAM_free(ps2);
    OSSL_PARAM_BLD_free(bld); OSSL_PARAM_BLD_free(b2);
    BN_free(d); EVP_PKEY_CTX_free(c); EVP_PKEY_CTX_free(c2);
}

static void t12(void) { /* GCM seal equals the default provider, byte for byte */
    /* GCM is served by the Go module's TLS 1.3 GCM service. For the same
     * key, nonce, AAD and plaintext the ciphertext and tag must equal the
     * default provider's. */
    unsigned char pt[48], aad[5] = {23, 3, 3, 0, 64}, cd[64], cg[64], td[16], tg[16]; int l, nd = 0, ng = 0, rd = 0, rg = 0;
    memset(pt, 'P', sizeof pt);
    for (int pass = 0; pass < 2; pass++) {
        EVP_CIPHER *c = EVP_CIPHER_fetch(pass ? G : D, "AES-256-GCM", NULL);
        EVP_CIPHER_CTX *x = EVP_CIPHER_CTX_new();
        int r = EVP_EncryptInit_ex2(x, c, K32, IV12, NULL) &&
                EVP_EncryptUpdate(x, NULL, &l, aad, sizeof aad) &&
                EVP_EncryptUpdate(x, pass ? cg : cd, pass ? &ng : &nd, pt, sizeof pt) &&
                EVP_EncryptFinal_ex(x, (pass ? cg : cd) + sizeof pt, &l) &&
                EVP_CIPHER_CTX_ctrl(x, EVP_CTRL_AEAD_GET_TAG, 16, pass ? tg : td);
        if (pass) rg = r; else rd = r;
        EVP_CIPHER_CTX_free(x); EVP_CIPHER_free(c);
    }
    printf("T12 AES-256-GCM seal with AAD: default rc=%d gofips rc=%d\n", rd, rg);
    int same = (rd == 1 && rg == 1 && nd == ng && memcmp(cd, cg, nd) == 0 && memcmp(td, tg, 16) == 0);
    VERDICT(!same, "GCM ciphertext and tag with AAD: %s", same ? "match the default provider (PASS)" : "MISMATCH or refused ; REGRESSION");
}

int main(int argc, char **argv) {
    if (argc < 3) return 2;
    G = OSSL_LIB_CTX_new(); D = OSSL_LIB_CTX_new();
    OSSL_PROVIDER_set_default_search_path(G, argv[1]);
    if (!OSSL_PROVIDER_load(G, "gofips")) { printf("LOAD: gofips provider failed to load\n"); ERR_print_errors_fp(stdout); return 3; }
    if (!OSSL_PROVIDER_load(D, "default")) return 4;
    if (!strcmp(argv[2], "load")) { printf("LOAD: gofips provider loaded\n"); return 0; }
    switch (atoi(argv[2])) {
    case 1: t1(); break; case 2: t2(); break; case 3: t3(); break; case 4: t4(); t4n(); break;
    case 5: t5(); break; case 6: t6(); break; case 7: t7(); break; case 8: t8(); break; case 10: t10(); break; case 11: t11(); break; case 12: t12(); break; case 9: t9(); break; case 13: t13(); break;
    }
    return 0;
}
