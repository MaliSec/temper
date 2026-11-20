/* sha3_pbkdf2.c: SHA-3, SHAKE, HMAC-SHA3, HKDF-SHA3 and PBKDF2 through
 * gofips, each compared with the default provider, plus the refusals that
 * keep PBKDF2 inside SP 5247's approved conditions (salt >= 128 bits,
 * derived key >= 112 bits, SHA-2 or SHA-3 HMAC), streaming ECDSA, large
 * KDF inputs and AES-CBC re-initialization.
 *
 * Build:  cc -o sha3_pbkdf2 sha3_pbkdf2.c $(pkg-config --cflags --libs openssl)
 * Run:    GODEBUG=fips140=on ./sha3_pbkdf2 <dir containing gofips.so>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/provider.h>

static OSSL_LIB_CTX *D, *G;
static int fails;
#define CHECK(c, msg) do { if (c) printf("PASS: %s\n", msg); else { printf("FAIL: %s\n", msg); fails++; } } while (0)

static const unsigned char MSG[] = "The quick brown fox jumps over the lazy dog";
static const unsigned char SALT16[16] = "0123456789abcdef";
static const unsigned char SALT15[15] = "0123456789abcde";

/* one-shot digest; xoflen > 0 for SHAKE. Returns output length or -1. */
static int digest(OSSL_LIB_CTX *L, const char *name, size_t xoflen, unsigned char *out) {
    EVP_MD *md = EVP_MD_fetch(L, name, NULL);
    EVP_MD_CTX *c = EVP_MD_CTX_new();
    unsigned int n = 0;
    int rc = -1;
    if (md && c && EVP_DigestInit_ex(c, md, NULL) && EVP_DigestUpdate(c, MSG, sizeof(MSG) - 1)) {
        if (xoflen) rc = EVP_DigestFinalXOF(c, out, xoflen) == 1 ? (int)xoflen : -1;
        else rc = EVP_DigestFinal_ex(c, out, &n) == 1 ? (int)n : -1;
    }
    EVP_MD_CTX_free(c);
    EVP_MD_free(md);
    return rc;
}

static void case_sha3(void) {
    const char *names[] = {"SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512"};
    for (int i = 0; i < 4; i++) {
        unsigned char a[64], b[64];
        int na = digest(D, names[i], 0, a), nb = digest(G, names[i], 0, b);
        char m[96];
        snprintf(m, sizeof m, "sha3: %s matches the default provider (%d bytes)", names[i], nb);
        CHECK(na > 0 && na == nb && memcmp(a, b, na) == 0, m);
    }
    const char *xofs[] = {"SHAKE-128", "SHAKE-256"};
    for (int i = 0; i < 2; i++) {
        unsigned char a[100], b[100];
        int na = digest(D, xofs[i], 100, a), nb = digest(G, xofs[i], 100, b);
        char m[96];
        snprintf(m, sizeof m, "sha3: %s with xoflen 100 matches the default provider", xofs[i]);
        CHECK(na == 100 && nb == 100 && memcmp(a, b, 100) == 0, m);
        /* no output length set: OpenSSL 4 refuses; gofips refuses on every version */
        unsigned char o[64];
        unsigned int n = 0;
        EVP_MD *md = EVP_MD_fetch(G, xofs[i], NULL);
        EVP_MD_CTX *c = EVP_MD_CTX_new();
        int ok = md && c && EVP_DigestInit_ex(c, md, NULL) && EVP_DigestUpdate(c, MSG, 3)
                 && EVP_DigestFinal_ex(c, o, &n) == 1;
        snprintf(m, sizeof m, "sha3: %s final without an output length is refused", xofs[i]);
        CHECK(!ok, m);
        EVP_MD_CTX_free(c);
        EVP_MD_free(md);
    }
    /* a copy taken mid-stream continues independently and still matches */
    EVP_MD *md = EVP_MD_fetch(G, "SHA3-256", NULL);
    EVP_MD_CTX *c = EVP_MD_CTX_new(), *d = EVP_MD_CTX_new();
    unsigned char x[32], y[32], want[32];
    unsigned int nx = 0, ny = 0;
    int ok = md && c && d && EVP_DigestInit_ex(c, md, NULL) && EVP_DigestUpdate(c, MSG, 10)
             && EVP_MD_CTX_copy_ex(d, c) && EVP_DigestUpdate(c, MSG + 10, sizeof(MSG) - 11)
             && EVP_DigestUpdate(d, MSG + 10, sizeof(MSG) - 11)
             && EVP_DigestFinal_ex(c, x, &nx) && EVP_DigestFinal_ex(d, y, &ny);
    CHECK(ok && digest(D, "SHA3-256", 0, want) == 32 && nx == 32 && ny == 32
          && memcmp(x, want, 32) == 0 && memcmp(y, want, 32) == 0,
          "sha3: a mid-stream copy of a SHA3-256 context matches the default provider");
    EVP_MD_CTX_free(c);
    EVP_MD_CTX_free(d);
    EVP_MD_free(md);
}

static int hmac(OSSL_LIB_CTX *L, const char *mdname, unsigned char *out) {
    static const unsigned char key[32] = "an HMAC key of thirty-two bytes!";
    size_t n = 0;
    unsigned char *r = EVP_Q_mac(L, "HMAC", NULL, mdname, NULL, key, sizeof key, MSG, sizeof(MSG) - 1, out, 64, &n);
    return r ? (int)n : -1;
}

static int hkdf(OSSL_LIB_CTX *L, const char *mdname, unsigned char *out, size_t outlen) {
    static unsigned char ikm[32] = "input keying material, 32 bytes";
    EVP_KDF *k = EVP_KDF_fetch(L, "HKDF", NULL);
    EVP_KDF_CTX *c = k ? EVP_KDF_CTX_new(k) : NULL;
    OSSL_PARAM p[4];
    p[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, (char *)mdname, 0);
    p[1] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, ikm, sizeof ikm);
    p[2] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, (void *)SALT16, sizeof SALT16);
    p[3] = OSSL_PARAM_construct_end();
    int rc = c && EVP_KDF_CTX_set_params(c, p) == 1 && EVP_KDF_derive(c, out, outlen, NULL) == 1;
    EVP_KDF_CTX_free(c);
    EVP_KDF_free(k);
    return rc;
}

static void case_mac_kdf(void) {
    const char *mds[] = {"SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512"};
    for (int i = 0; i < 4; i++) {
        unsigned char a[64], b[64];
        int na = hmac(D, mds[i], a), nb = hmac(G, mds[i], b);
        char m[96];
        snprintf(m, sizeof m, "hmac: HMAC-%s matches the default provider", mds[i]);
        CHECK(na > 0 && na == nb && memcmp(a, b, na) == 0, m);
    }
    const char *kmds[] = {"SHA3-256", "SHA3-512", "SHA2-512"};
    for (int i = 0; i < 3; i++) {
        unsigned char a[48], b[48];
        char m[96];
        snprintf(m, sizeof m, "hkdf: HKDF-%s (digest via set_ctx_params) matches the default provider", kmds[i]);
        CHECK(hkdf(D, kmds[i], a, 48) && hkdf(G, kmds[i], b, 48) && memcmp(a, b, 48) == 0, m);
    }
}

/* PBKDF2 through EVP_KDF with every parameter set explicitly. */
static int pbkdf2(OSSL_LIB_CTX *L, const char *mdname, const unsigned char *salt, size_t saltlen,
                  int iter, unsigned char *out, size_t outlen) {
    static unsigned char pass[] = "correct horse battery staple";
    EVP_KDF *k = EVP_KDF_fetch(L, "PBKDF2", NULL);
    EVP_KDF_CTX *c = k ? EVP_KDF_CTX_new(k) : NULL;
    OSSL_PARAM p[5], *q = p;
    *q++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD, pass, sizeof(pass) - 1);
    *q++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, (void *)salt, saltlen);
    *q++ = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_ITER, &iter);
    if (mdname) *q++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, (char *)mdname, 0);
    *q = OSSL_PARAM_construct_end();
    int rc = c && EVP_KDF_derive(c, out, outlen, p) == 1;
    EVP_KDF_CTX_free(c);
    EVP_KDF_free(k);
    return rc;
}

static void case_pbkdf2(void) {
    const char *mds[] = {"SHA2-256", "SHA2-512", "SHA3-256"};
    for (int i = 0; i < 3; i++) {
        unsigned char a[32], b[32];
        char m[96];
        snprintf(m, sizeof m, "pbkdf2: PBKDF2-HMAC-%s matches the default provider", mds[i]);
        CHECK(pbkdf2(D, mds[i], SALT16, 16, 1000, a, 32) && pbkdf2(G, mds[i], SALT16, 16, 1000, b, 32)
              && memcmp(a, b, 32) == 0, m);
    }
    /* PKCS5_PBKDF2_HMAC, the call Python's hashlib.pbkdf2_hmac makes */
    unsigned char a[32], b[32];
    static const char pw[] = "correct horse battery staple";
    EVP_MD *dmd = EVP_MD_fetch(D, "SHA2-256", NULL), *gmd = EVP_MD_fetch(G, "SHA2-256", NULL);
    OSSL_LIB_CTX *prev = OSSL_LIB_CTX_set0_default(D);
    int ra = PKCS5_PBKDF2_HMAC(pw, sizeof(pw) - 1, SALT16, 16, 100000, dmd, 32, a);
    OSSL_LIB_CTX_set0_default(G);
    int rb = PKCS5_PBKDF2_HMAC(pw, sizeof(pw) - 1, SALT16, 16, 100000, gmd, 32, b);
    OSSL_LIB_CTX_set0_default(prev);
    CHECK(ra == 1 && rb == 1 && memcmp(a, b, 32) == 0,
          "pbkdf2: PKCS5_PBKDF2_HMAC (100000 iterations) matches the default provider");
    EVP_MD_free(dmd);
    EVP_MD_free(gmd);

    unsigned char o[32];
    CHECK(!pbkdf2(G, "SHA2-256", SALT15, 15, 1000, o, 32), "pbkdf2: a salt under 128 bits is refused (SP 5247 Table 8)");
    CHECK(!pbkdf2(G, "SHA2-256", SALT16, 16, 1000, o, 13), "pbkdf2: a derived key under 112 bits is refused (IG C.M)");
    CHECK(pbkdf2(G, "SHA2-256", SALT16, 16, 1000, o, 14), "pbkdf2: a 112-bit derived key is accepted");
    CHECK(!pbkdf2(G, "SHA1", SALT16, 16, 1000, o, 32), "pbkdf2: HMAC-SHA1 is refused (not approved for PBKDF2)");
    CHECK(!pbkdf2(G, NULL, SALT16, 16, 1000, o, 32), "pbkdf2: no digest set is refused (no SHA-1 default)");
    CHECK(!pbkdf2(G, "SHA2-256", SALT16, 16, 0, o, 32), "pbkdf2: zero iterations are refused");
    CHECK(!pbkdf2(G, "SHA2-256", SALT16, 16, -5, o, 32), "pbkdf2: a negative iteration count is refused");
}

/* Streaming ECDSA (EVP_DigestSignUpdate/Final), the shape node:crypto and
 * WebCrypto use. The one-shot verify is differentially tested elsewhere. */
static int stream_sign(EVP_PKEY *k, const char *md, EVP_MD_CTX **mid, unsigned char *sig, size_t *siglen) {
    EVP_MD_CTX *m = EVP_MD_CTX_new();
    size_t n = 0;
    int ok = EVP_DigestSignInit_ex(m, NULL, md, G, NULL, k, NULL) == 1
          && EVP_DigestSignUpdate(m, MSG, 10) == 1;
    if (ok && mid) { *mid = EVP_MD_CTX_new(); ok = EVP_MD_CTX_copy_ex(*mid, m) == 1; }
    ok = ok && EVP_DigestSignUpdate(m, MSG + 10, sizeof(MSG) - 1 - 10) == 1
            && EVP_DigestSignFinal(m, NULL, &n) == 1 && n >= 72
            && EVP_DigestSignFinal(m, sig, &n) == 1;
    *siglen = n;
    EVP_MD_CTX_free(m);
    return ok;
}

static int verify(EVP_PKEY *k, const char *md, int streaming, const unsigned char *msg, size_t msglen,
                  const unsigned char *sig, size_t siglen) {
    EVP_MD_CTX *m = EVP_MD_CTX_new();
    int ok = EVP_DigestVerifyInit_ex(m, NULL, md, G, NULL, k, NULL) == 1;
    if (streaming)
        ok = ok && EVP_DigestVerifyUpdate(m, msg, 5) == 1 && EVP_DigestVerifyUpdate(m, msg + 5, msglen - 5) == 1
                && EVP_DigestVerifyFinal(m, sig, siglen) == 1;
    else
        ok = ok && EVP_DigestVerify(m, sig, siglen, msg, msglen) == 1;
    EVP_MD_CTX_free(m);
    return ok;
}

static void case_ecdsa_stream(void) {
    EVP_PKEY *k = EVP_PKEY_Q_keygen(G, NULL, "EC", "P-256");
    CHECK(k != NULL, "ecdsa: P-256 key generated");
    if (!k) return;
    const char *mds[] = {"SHA2-256", "SHA2-384"};
    for (int i = 0; i < 2; i++) {
        unsigned char sig[80], sig2[80], tampered[sizeof(MSG)];
        size_t n = 0, n2 = 0;
        EVP_MD_CTX *mid = NULL;
        int ok = stream_sign(k, mds[i], &mid, sig, &n);
        printf("  %s: streaming sign %s\n", mds[i], ok ? "ok" : "FAILED");
        CHECK(ok, "ecdsa: streaming DigestSignUpdate/Final signs");
        CHECK(ok && verify(k, mds[i], 0, MSG, sizeof(MSG) - 1, sig, n), "ecdsa: a streaming signature verifies one-shot");
        CHECK(ok && verify(k, mds[i], 1, MSG, sizeof(MSG) - 1, sig, n), "ecdsa: a streaming signature verifies streaming");
        memcpy(tampered, MSG, sizeof(MSG));
        tampered[3] ^= 1;
        CHECK(ok && !verify(k, mds[i], 1, tampered, sizeof(MSG) - 1, sig, n), "ecdsa: streaming verify rejects a changed message");
        ok = mid && EVP_DigestSignUpdate(mid, MSG + 10, sizeof(MSG) - 1 - 10) == 1
               && EVP_DigestSignFinal(mid, NULL, &n2) == 1 && EVP_DigestSignFinal(mid, sig2, &n2) == 1;
        CHECK(ok && verify(k, mds[i], 0, MSG, sizeof(MSG) - 1, sig2, n2), "ecdsa: a context copied mid-stream signs the same message");
        EVP_MD_CTX_free(mid);
    }
    EVP_PKEY_free(k);
}

/* Large inputs and AES-CBC re-initialization, against the default
 * provider. */
static int kdf_big(OSSL_LIB_CTX *L, const char *alg, const char *bigname, unsigned char *big, size_t biglen,
                   unsigned char *out) {
    static unsigned char ikm[32] = "input keying material, 32 bytes";
    int iter = 1;
    EVP_KDF *k = EVP_KDF_fetch(L, alg, NULL);
    EVP_KDF_CTX *c = k ? EVP_KDF_CTX_new(k) : NULL;
    OSSL_PARAM p[5], *q = p;
    *q++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, "SHA2-256", 0);
    *q++ = OSSL_PARAM_construct_octet_string(bigname, big, biglen);
    if (strcmp(alg, "PBKDF2") == 0) {
        *q++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, (void *)SALT16, 16);
        *q++ = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_ITER, &iter);
    } else {
        *q++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, ikm, sizeof ikm);
    }
    *q = OSSL_PARAM_construct_end();
    int rc = c && EVP_KDF_derive(c, out, 32, p) == 1;
    EVP_KDF_CTX_free(c);
    EVP_KDF_free(k);
    return rc;
}

static int cbc_reinit(OSSL_LIB_CTX *L, int reiv, unsigned char *out) {
    static const unsigned char key[32] = "an AES-256 key of thirty-two by!", iv1[16] = "first IV, 16 byt",
                               iv2[16] = "second IV, 16 by", pt[32] = "two blocks of plaintext, 32 byte";
    EVP_CIPHER *ci = EVP_CIPHER_fetch(L, "AES-256-CBC", NULL);
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    int l1 = 0, l2 = 0, l3 = 0;
    int ok = ci && EVP_CipherInit_ex2(c, ci, key, iv1, 1, NULL) == 1 && EVP_CIPHER_CTX_set_padding(c, 0) == 1
             && EVP_CipherUpdate(c, out, &l1, pt, 32) == 1 && EVP_CipherFinal_ex(c, out + l1, &l2) == 1
             && EVP_CipherInit_ex2(c, NULL, NULL, reiv ? iv2 : NULL, 1, NULL) == 1
             && EVP_CipherUpdate(c, out, &l3, pt, 32) == 1 && l3 == 32;
    EVP_CIPHER_CTX_free(c);
    EVP_CIPHER_free(ci);
    return ok;
}

/* GCM tag reads and sets: default-provider lengths in the approved range,
 * refusals elsewhere (a read that "succeeds" must write the tag). */
static int gcm_tag(OSSL_LIB_CTX *L, size_t want, unsigned char *tag) {
    static const unsigned char key[32] = "an AES-256 key of thirty-two by!", iv[12] = "twelve bytes", pt[20] = "nineteen-byte input";
    EVP_CIPHER *ci = EVP_CIPHER_fetch(L, "AES-256-GCM", NULL);
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    unsigned char ct[64];
    int l = 0, l2 = 0;
    memset(tag, 0xaa, 16);
    int ok = ci && EVP_EncryptInit_ex2(c, ci, key, iv, NULL) == 1 && EVP_EncryptUpdate(c, ct, &l, pt, sizeof pt) == 1
             && EVP_EncryptFinal_ex(c, ct + l, &l2) == 1 && EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_GET_TAG, (int)want, tag) == 1;
    EVP_CIPHER_CTX_free(c);
    EVP_CIPHER_free(ci);
    return ok;
}

static int hkdf_mode(OSSL_LIB_CTX *L, const char *mode, unsigned char *out, size_t n) {
    static unsigned char ikm[32] = "input keying material, 32 bytes";
    EVP_KDF *k = EVP_KDF_fetch(L, "HKDF", NULL);
    EVP_KDF_CTX *c = k ? EVP_KDF_CTX_new(k) : NULL;
    OSSL_PARAM p[5] = {
        OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, "SHA2-256", 0),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, ikm, sizeof ikm),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, (void *)SALT16, 16),
        OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_MODE, (char *)mode, 0),
        OSSL_PARAM_construct_end(),
    };
    int ok = c && EVP_KDF_derive(c, out, n, p) == 1;
    EVP_KDF_CTX_free(c);
    EVP_KDF_free(k);
    return ok;
}

static int hmac_rekey(OSSL_LIB_CTX *L, unsigned char *out) {
    static const unsigned char k1[32] = "the first HMAC key, 32 bytes!!!", k2[32] = "a second HMAC key, also 32 bytes";
    EVP_MAC *m = EVP_MAC_fetch(L, "HMAC", NULL);
    EVP_MAC_CTX *c = m ? EVP_MAC_CTX_new(m) : NULL;
    OSSL_PARAM d[2] = {OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, "SHA2-256", 0), OSSL_PARAM_construct_end()};
    OSSL_PARAM kp[2] = {OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_KEY, (void *)k2, 32), OSSL_PARAM_construct_end()};
    size_t n = 0;
    int ok = c && EVP_MAC_init(c, k1, 32, d) == 1 && EVP_MAC_CTX_set_params(c, kp) == 1
             && EVP_MAC_update(c, MSG, sizeof MSG) == 1 && EVP_MAC_final(c, out, &n, 32) == 1 && n == 32;
    EVP_MAC_CTX_free(c);
    EVP_MAC_free(m);
    return ok;
}

/* Init with SHA2-256, set the digest to `name` (refused or not), dup the
 * fresh ctx, then MAC with original and dup. */
static int hmac_digest_change_dup(OSSL_LIB_CTX *L, const char *name, int *set_ok, unsigned char *o1, unsigned char *o2) {
    static const unsigned char k[32] = "the first HMAC key, 32 bytes!!!";
    EVP_MAC *m = EVP_MAC_fetch(L, "HMAC", NULL);
    EVP_MAC_CTX *c = m ? EVP_MAC_CTX_new(m) : NULL, *dup = NULL;
    OSSL_PARAM d[2] = {OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, "SHA2-256", 0), OSSL_PARAM_construct_end()};
    OSSL_PARAM d2[2] = {OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, (char *)name, 0), OSSL_PARAM_construct_end()};
    size_t n1 = 0, n2 = 0;
    int ok = c && EVP_MAC_init(c, k, 32, d) == 1;
    if (ok) {
        *set_ok = EVP_MAC_CTX_set_params(c, d2);
        ok = (dup = EVP_MAC_CTX_dup(c)) != NULL
             && EVP_MAC_update(c, MSG, sizeof MSG) == 1 && EVP_MAC_final(c, o1, &n1, 64) == 1
             && EVP_MAC_update(dup, MSG, sizeof MSG) == 1 && EVP_MAC_final(dup, o2, &n2, 64) == 1
             && n1 == 32 && n2 == 32;
    }
    EVP_MAC_CTX_free(dup);
    EVP_MAC_CTX_free(c);
    EVP_MAC_free(m);
    return ok;
}

static void case_params(void) {
    unsigned char g[64], d[64];
    CHECK(gcm_tag(G, 16, g) && gcm_tag(D, 16, d) && memcmp(g, d, 16) == 0, "gcm: a 16-byte tag read matches the default provider");
    CHECK(gcm_tag(G, 12, g) && gcm_tag(D, 12, d) && memcmp(g, d, 12) == 0, "gcm: a 12-byte tag read returns the tag's first 12 bytes");
    CHECK(!gcm_tag(G, 4, g) && !gcm_tag(G, 0, g) && !gcm_tag(G, 17, g), "gcm: tag reads under 96 bits, of 0 or over 16 bytes are refused");
    CHECK(hkdf_mode(G, "EXTRACT_ONLY", g, 32) && hkdf_mode(D, "EXTRACT_ONLY", d, 32) && memcmp(g, d, 32) == 0,
          "hkdf: mode EXTRACT_ONLY by name returns the PRK, as the default provider");
    CHECK(hkdf_mode(G, "EXTRACT_AND_EXPAND", g, 42) && hkdf_mode(D, "EXTRACT_AND_EXPAND", d, 42) && memcmp(g, d, 42) == 0,
          "hkdf: mode EXTRACT_AND_EXPAND by name matches the default provider");
    CHECK(!hkdf_mode(G, "EXTRACT_SOMETIMES", g, 32), "hkdf: an unknown mode is refused");
    CHECK(hmac_rekey(G, g) && hmac_rekey(D, d) && memcmp(g, d, 32) == 0, "hmac: a key set after init re-keys, as the default provider");
    unsigned char g2[64], d2[64];
    int gs = -1, ds = -1;
    CHECK(hmac_digest_change_dup(G, "MD5", &gs, g, g2) && gs == 0 && memcmp(g, g2, 32) == 0,
          "hmac: a refused digest change leaves the ctx usable, and its dup matches it");
    CHECK(hmac_digest_change_dup(G, "SHA2-512", &gs, g, g2) && hmac_digest_change_dup(D, "SHA2-512", &ds, d, d2)
          && gs == 1 && memcmp(g, d, 32) == 0 && memcmp(g2, d2, 32) == 0 && memcmp(g, g2, 32) == 0,
          "hmac: a digest change after init applies at the next keying; the dup matches, as the default provider");
}

static void case_edges(void) {
    size_t n = (1 << 20) + 1;
    unsigned char *big = malloc(n), a[32], b[32], e[32];
    memset(big, 'p', n);
    CHECK(kdf_big(G, "PBKDF2", OSSL_KDF_PARAM_PASSWORD, big, n, a) && kdf_big(D, "PBKDF2", OSSL_KDF_PARAM_PASSWORD, big, n, b)
          && memcmp(a, b, 32) == 0 && kdf_big(G, "PBKDF2", OSSL_KDF_PARAM_PASSWORD, big, 0, e) && memcmp(a, e, 32) != 0,
          "pbkdf2: a 1 MiB + 1 password is used, not dropped (matches the default provider, differs from empty)");
    CHECK(kdf_big(G, "HKDF", OSSL_KDF_PARAM_SALT, big, n, a) && kdf_big(D, "HKDF", OSSL_KDF_PARAM_SALT, big, n, b)
          && memcmp(a, b, 32) == 0, "hkdf: a 1 MiB + 1 salt matches the default provider");
    free(big);
    unsigned char g[32], d[32];
    CHECK(cbc_reinit(G, 1, g) && cbc_reinit(D, 1, d) && memcmp(g, d, 32) == 0,
          "aes-256-cbc: a key-less re-init with a new IV uses that IV (matches the default provider)");
    CHECK(cbc_reinit(G, 0, g) && cbc_reinit(D, 0, d) && memcmp(g, d, 32) == 0,
          "aes-256-cbc: a key-less re-init without an IV restarts from the IV as set (matches the default provider)");
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <dir containing gofips.so>\n", argv[0]); return 2; }
    D = OSSL_LIB_CTX_new();
    G = OSSL_LIB_CTX_new();
    if (!OSSL_PROVIDER_load(D, "default")) { printf("default provider failed to load\n"); return 2; }
    OSSL_PROVIDER_set_default_search_path(G, argv[1]);
    if (!OSSL_PROVIDER_load(G, "gofips") || !OSSL_PROVIDER_load(G, "base")) { printf("gofips/base provider failed to load\n"); return 2; }
    case_sha3();
    case_mac_kdf();
    case_pbkdf2();
    case_edges();
    case_params();
    case_ecdsa_stream();
    printf(fails ? "SHA3PBKDF2: %d FAILURES\n" : "SHA3PBKDF2: ALL PASS\n", fails);
    return fails ? 1 : 0;
}
