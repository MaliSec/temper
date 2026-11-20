/* tls12.c: TLS 1.2 through gofips, against the default provider.
 *
 *   1. TLS1-PRF matches the default provider for SHA-256/384/512 and
 *      refuses the classic master secret, SHA-1 and MD5-SHA1.
 *   2. TLS 1.2 handshakes (ECDHE with ECDSA or RSA certificates, AES-GCM)
 *      with gofips on one or both ends: records of many sizes both ways,
 *      the provider's counters, and session resumption.
 *   3. Refusals: a peer without the extended master secret, CBC and
 *      ChaCha20 suites, RSA key exchange.
 *   4. GCM nonce rules, AAD order, IV queries, CBC copies and parameter
 *      handling, checked directly through EVP.
 *
 * Build:  cc -o tls12 tls12.c $(pkg-config --cflags --libs openssl)
 * Run:    GODEBUG=fips140=on ./tls12 <dir containing gofips.so>
 */
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/provider.h>
#include <openssl/params.h>
#include <dlfcn.h>
#include <stdint.h>

static OSSL_LIB_CTX *D, *G;
static OSSL_PROVIDER *GP;
static char so_path[4096];
static int fails;

#define CHECK(cond, ...) do { \
    if (cond) { printf("PASS: "); } else { printf("FAIL: "); fails++; } \
    printf(__VA_ARGS__); printf("\n"); } while (0)

/* cipher operations served by gofips so far (the provider's own counter) */
static long gofips_cipher_ops(void) {
    char *json = NULL;
    OSSL_PARAM p[2] = { OSSL_PARAM_construct_utf8_ptr("temperfips-ops", &json, 0), OSSL_PARAM_construct_end() };
    if (!OSSL_PROVIDER_get_params(GP, p) || json == NULL) return -1;
    const char *c = strstr(json, "\"cipher\":");
    return c ? atol(c + 9) : 0;
}

/* a key (EC P-256, or RSA-2048 when rsa is set) and a self-signed
 * certificate, made with the default provider */
static int make_identity_kind(int rsa, char **keypem, long *keylen, char **certpem, long *certlen) {
    EVP_PKEY *k = rsa ? EVP_PKEY_Q_keygen(D, NULL, "RSA", (size_t)2048) : EVP_PKEY_Q_keygen(D, NULL, "EC", "prime256v1");
    X509 *x = X509_new_ex(D, NULL);
    if (!k || !x) return 0;
    X509_set_version(x, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(x), 1);
    X509_gmtime_adj(X509_getm_notBefore(x), -3600);
    X509_gmtime_adj(X509_getm_notAfter(x), 86400);
    X509_set_pubkey(x, k);
    X509_NAME *n = X509_NAME_new();
    X509_NAME_add_entry_by_txt(n, "CN", MBSTRING_ASC, (const unsigned char *)"gofips-test", -1, -1, 0);
    X509_set_subject_name(x, n);
    X509_set_issuer_name(x, n);
    X509_NAME_free(n);
    if (!X509_sign(x, k, EVP_sha256())) return 0;
    BIO *b = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(b, k, NULL, NULL, 0, NULL, NULL);
    char *d; *keylen = BIO_get_mem_data(b, &d); *keypem = malloc(*keylen); memcpy(*keypem, d, *keylen); BIO_free(b);
    b = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(b, x);
    *certlen = BIO_get_mem_data(b, &d); *certpem = malloc(*certlen); memcpy(*certpem, d, *certlen); BIO_free(b);
    EVP_PKEY_free(k); X509_free(x);
    return 1;
}

static SSL_CTX *make_ctx(OSSL_LIB_CTX *L, int server, const char *suite,
                         const char *keypem, long keylen, const char *certpem, long certlen) {
    SSL_CTX *c = SSL_CTX_new_ex(L, NULL, server ? TLS_server_method() : TLS_client_method());
    if (!c) return NULL;
    SSL_CTX_set_min_proto_version(c, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(c, TLS1_2_VERSION);
    if (!SSL_CTX_set_cipher_list(c, suite)) return NULL;
    if (!SSL_CTX_set1_groups_list(c, "secp256r1:secp384r1")) return NULL;
    SSL_CTX_set_verify(c, SSL_VERIFY_NONE, NULL);
    if (server) {
        BIO *b = BIO_new_mem_buf(certpem, (int)certlen);
        X509 *x = PEM_read_bio_X509(b, NULL, NULL, NULL); BIO_free(b);
        b = BIO_new_mem_buf(keypem, (int)keylen);
        EVP_PKEY *k = PEM_read_bio_PrivateKey_ex(b, NULL, NULL, NULL, L, NULL); BIO_free(b);
        if (!x || !k) return NULL;
        if (SSL_CTX_use_certificate(c, x) != 1 || SSL_CTX_use_PrivateKey(c, k) != 1) return NULL;
        X509_free(x); EVP_PKEY_free(k);
    }
    return c;
}

/* drive both ends until neither wants more, for handshake and KeyUpdate */
static int pump_handshake(SSL *cl, SSL *sv) {
    for (int i = 0; i < 200; i++) {
        int a = SSL_is_init_finished(cl) ? 1 : SSL_do_handshake(cl);
        int b = SSL_is_init_finished(sv) ? 1 : SSL_do_handshake(sv);
        if (a == 1 && b == 1) return 1;
        int ea = a == 1 ? SSL_ERROR_NONE : SSL_get_error(cl, a);
        int eb = b == 1 ? SSL_ERROR_NONE : SSL_get_error(sv, b);
        if ((ea != SSL_ERROR_NONE && ea != SSL_ERROR_WANT_READ && ea != SSL_ERROR_WANT_WRITE) ||
            (eb != SSL_ERROR_NONE && eb != SSL_ERROR_WANT_READ && eb != SSL_ERROR_WANT_WRITE)) return 0;
    }
    return 0;
}

/* send n bytes from -> to and check them; returns 1 if every byte arrived intact */
static int send_check(SSL *from, SSL *to, size_t n, unsigned seed) {
    static unsigned char out[20000], in[20000];
    for (size_t i = 0; i < n; i++) out[i] = (unsigned char)(seed * 131u + i * 7u);
    size_t done = 0;
    while (done < n) {
        int w = SSL_write(from, out + done, (int)(n - done));
        if (w <= 0) return 0;
        done += (size_t)w;
    }
    size_t got = 0;
    for (int tries = 0; got < n && tries < 64; tries++) {
        int r = SSL_read(to, in + got, (int)(n - got));
        if (r > 0) got += (size_t)r;
        else if (SSL_get_error(to, r) != SSL_ERROR_WANT_READ) return 0;
    }
    return got == n && memcmp(in, out, n) == 0;
}

static int exchange(SSL *cl, SSL *sv, int rounds, unsigned seed) {
    static const size_t sizes[] = {1, 2, 15, 16, 17, 255, 1024, 4096, 16383, 16384};
    for (int i = 0; i < rounds; i++) {
        size_t n = sizes[i % (int)(sizeof sizes / sizeof sizes[0])];
        if (!send_check(cl, sv, n, seed + (unsigned)i)) return -(i * 2 + 1);
        if (!send_check(sv, cl, n, seed + 7777u + (unsigned)i)) return -(i * 2 + 2);
    }
    return rounds * 2;
}


static long gofips_ops(const char *name) {
    char *json = NULL, key[32];
    OSSL_PARAM p[2] = { OSSL_PARAM_construct_utf8_ptr("temperfips-ops", &json, 0), OSSL_PARAM_construct_end() };
    if (!OSSL_PROVIDER_get_params(GP, p) || json == NULL) return -1;
    snprintf(key, sizeof key, "\"%s\":", name);
    const char *c = strstr(json, key);
    return c ? atol(c + strlen(key)) : 0;
}

/* TLS1-PRF with the label and seeds as separate seed parameters, as libssl passes them */
static int prf(OSSL_LIB_CTX *L, const char *md, const char *label, unsigned char *out, size_t n) {
    static const unsigned char secret[48] = "a pre-master secret of forty-eight bytes......";
    static const unsigned char s1[32] = "client random, thirty-two bytes", s2[32] = "server random, thirty-two bytes";
    EVP_KDF *k = EVP_KDF_fetch(L, "TLS1-PRF", NULL);
    EVP_KDF_CTX *c = k ? EVP_KDF_CTX_new(k) : NULL;
    OSSL_PARAM p[6], *q = p;
    *q++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, (char *)md, 0);
    *q++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SECRET, (void *)secret, sizeof secret);
    *q++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SEED, (void *)label, strlen(label));
    *q++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SEED, (void *)s1, sizeof s1);
    *q++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SEED, (void *)s2, sizeof s2);
    *q = OSSL_PARAM_construct_end();
    int ok = c && EVP_KDF_derive(c, out, n, p) == 1;
    EVP_KDF_CTX_free(c);
    EVP_KDF_free(k);
    return ok;
}

static void case_prf(void) {
    unsigned char g[104], d[104];
    const char *mds[] = {"SHA2-256", "SHA2-384", "SHA2-512"};
    for (int i = 0; i < 3; i++) {
        CHECK(prf(G, mds[i], "key expansion", g, sizeof g) && prf(D, mds[i], "key expansion", d, sizeof d) && memcmp(g, d, sizeof g) == 0,
              "tls1-prf: %s key expansion matches the default provider", mds[i]);
        CHECK(prf(G, mds[i], "extended master secret", g, 48) && prf(D, mds[i], "extended master secret", d, 48) && memcmp(g, d, 48) == 0,
              "tls1-prf: %s extended master secret matches the default provider", mds[i]);
    }
    CHECK(prf(D, "SHA2-256", "master secret", d, 48) && !prf(G, "SHA2-256", "master secret", g, 48),
          "tls1-prf: the master secret without the extended master secret is refused");
    CHECK(!prf(G, "SHA1", "key expansion", g, 32), "tls1-prf: SHA-1 is refused");
    CHECK(!prf(G, "MD5-SHA1", "key expansion", g, 32), "tls1-prf: MD5-SHA1 (TLS 1.0/1.1) is refused");
    CHECK(!prf(G, "SHA3-256", "key expansion", g, 32), "tls1-prf: SHA3-256 is refused");
    {
        EVP_KDF *k = EVP_KDF_fetch(G, "TLS1-PRF", NULL);
        EVP_KDF_CTX *c = k ? EVP_KDF_CTX_new(k) : NULL;
        static const unsigned char s13[13] = "short secret";
        OSSL_PARAM p[4] = {OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, "SHA2-256", 0),
                           OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SECRET, (void *)s13, sizeof s13),
                           OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SEED, "key expansion", 13), OSSL_PARAM_construct_end()};
        CHECK(c && EVP_KDF_derive(c, g, 32, p) <= 0, "tls1-prf: a secret under 112 bits is refused");
        EVP_KDF_CTX_free(c);
        EVP_KDF_free(k);
    }
}


/* One TLS 1.2 GCM record through EVP: AAD (13 bytes), then the record in
 * place (explicit nonce, data, tag). Returns 1 and the 8-byte explicit
 * nonce on success. */
static int tls12_seal(EVP_CIPHER_CTX *c, unsigned char *nonce8) {
    unsigned char rec[8 + 5 + 16] = {0}, aad[13] = {0, 0, 0, 0, 0, 0, 0, 1, 23, 3, 3, 0, 8 + 5};
    int l = 0;
    memcpy(rec + 8, "hello", 5);
    if (EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_TLS1_AAD, 13, aad) <= 0) return 0;
    if (EVP_EncryptUpdate(c, rec, &l, rec, sizeof rec) != 1 || l != (int)sizeof rec) return 0;
    memcpy(nonce8, rec, 8);
    return 1;
}

static EVP_CIPHER_CTX *tls12_ctx(EVP_CIPHER *ci, const unsigned char *key, int fixed) {
    static const unsigned char iv4[4] = {1, 2, 3, 4};
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    if (!c || EVP_EncryptInit_ex(c, ci, NULL, key, NULL) != 1) return c;
    if (fixed) EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IV_FIXED, 4, (void *)iv4);
    return c;
}

/* Nonce uniqueness per key, across the ways a caller could restart a
 * TLS 1.2 nonce sequence. */
static void case_nonce(void) {
    static const unsigned char key[16] = "a GCM key, 16 b", iv4[4] = {1, 2, 3, 4}, iv12[12] = {1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0};
    EVP_CIPHER *ci = EVP_CIPHER_fetch(G, "AES-128-GCM", NULL);
    unsigned char n1[8], n2[8];
    EVP_CIPHER_CTX *a = tls12_ctx(ci, key, 1);
    CHECK(tls12_seal(a, n1), "tls12 gcm: a record seals");
    CHECK(EVP_CIPHER_CTX_ctrl(a, EVP_CTRL_GCM_SET_IV_FIXED, 4, (void *)iv4) <= 0,
          "tls12 gcm: a second fixed IV on the same ctx is refused");
    EVP_CIPHER_CTX *b = EVP_CIPHER_CTX_new();
    CHECK(EVP_CIPHER_CTX_copy(b, a) == 1 && EVP_CIPHER_CTX_ctrl(b, EVP_CTRL_GCM_SET_IV_FIXED, 4, (void *)iv4) <= 0,
          "tls12 gcm: a fixed IV on a copy is refused (the copy shares the counter)");
    CHECK(tls12_seal(b, n2) && memcmp(n1, n2, 8) != 0, "tls12 gcm: a copy continues the original's nonce sequence");
    CHECK(EVP_EncryptInit_ex(a, NULL, NULL, key, NULL) == 1 && EVP_CIPHER_CTX_ctrl(a, EVP_CTRL_GCM_SET_IV_FIXED, 4, (void *)iv4) <= 0,
          "tls12 gcm: a re-init with the same key keeps the sequence (fixed IV refused)");
    int l = 0; unsigned char out[32];
    CHECK(!(EVP_EncryptInit_ex(a, NULL, NULL, NULL, iv12) == 1 && EVP_EncryptUpdate(a, out, &l, (const unsigned char *)"x", 1) == 1
            && EVP_EncryptFinal_ex(a, out + l, &l) == 1),
          "tls12 gcm: TLS 1.3-style records are refused once the key is in TLS 1.2 mode");
    EVP_CIPHER_CTX *t13 = tls12_ctx(ci, key, 0);
    CHECK(EVP_EncryptInit_ex(t13, NULL, NULL, NULL, iv12) == 1 && EVP_EncryptUpdate(t13, out, &l, (const unsigned char *)"x", 1) == 1
          && EVP_EncryptFinal_ex(t13, out + l, &l) == 1
          && EVP_CIPHER_CTX_ctrl(t13, EVP_CTRL_GCM_SET_IV_FIXED, 4, (void *)iv4) <= 0,
          "tls12 gcm: a key that protected a TLS 1.3 record cannot switch to TLS 1.2 mode");
    EVP_CIPHER_CTX *c1 = tls12_ctx(ci, key, 1), *c2 = tls12_ctx(ci, key, 1);
    CHECK(tls12_seal(c1, n1) && tls12_seal(c2, n2) && memcmp(n1, n2, 8) != 0,
          "tls12 gcm: two separate ctxs with the same key start at different explicit nonces");
    EVP_CIPHER_CTX_free(a); EVP_CIPHER_CTX_free(b); EVP_CIPHER_CTX_free(t13); EVP_CIPHER_CTX_free(c1); EVP_CIPHER_CTX_free(c2);

    static const unsigned char key2[16] = "another GCM key";
    EVP_CIPHER_CTX *r = tls12_ctx(ci, key, 0);
    CHECK(EVP_EncryptInit_ex(r, NULL, NULL, NULL, iv12) == 1 && EVP_EncryptUpdate(r, out, &l, (const unsigned char *)"x", 1) == 1
          && EVP_EncryptFinal_ex(r, out + l, &l) == 1 && EVP_EncryptInit_ex(r, NULL, NULL, key2, iv12) == 1
          && EVP_EncryptInit_ex(r, NULL, NULL, key, iv12) != 1,
          "gcm: an encrypt ctx cannot return to a key it sealed under before");
    EVP_CIPHER_CTX *p0 = tls12_ctx(ci, key, 0), *p1 = EVP_CIPHER_CTX_new();
    CHECK(EVP_CIPHER_CTX_copy(p1, p0) == 1 && EVP_CIPHER_CTX_ctrl(p0, EVP_CTRL_GCM_SET_IV_FIXED, 4, (void *)iv4) > 0
          && EVP_CIPHER_CTX_ctrl(p1, EVP_CTRL_GCM_SET_IV_FIXED, 4, (void *)iv4) <= 0,
          "tls12 gcm: a copy taken before the fixed IV cannot start its own sequence");
    EVP_CIPHER_CTX *e = tls12_ctx(ci, key, 0);
    CHECK(EVP_DecryptInit_ex(e, NULL, NULL, NULL, iv12) != 1, "gcm: a keyless re-init cannot switch an encrypt ctx to decrypt");
    EVP_CIPHER_CTX_free(r); EVP_CIPHER_CTX_free(p0); EVP_CIPHER_CTX_free(p1); EVP_CIPHER_CTX_free(e);
    EVP_CIPHER_free(ci);
}


/* AES-GCM with the same key, nonce, AAD and plaintext through the default
 * provider: ct (len n) then the 16-byte tag. */
static int default_gcm(const unsigned char *key, const unsigned char *iv, const unsigned char *aad, int aadl,
                       const unsigned char *pt, int n, unsigned char *ct_tag) {
    EVP_CIPHER *ci = EVP_CIPHER_fetch(D, "AES-128-GCM", NULL);
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    int l = 0, f = 0;
    int ok = ci && c && EVP_EncryptInit_ex(c, ci, NULL, key, iv) == 1
             && EVP_EncryptUpdate(c, NULL, &l, aad, aadl) == 1
             && EVP_EncryptUpdate(c, ct_tag, &l, pt, n) == 1
             && EVP_EncryptFinal_ex(c, ct_tag + l, &f) == 1
             && EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_GET_TAG, 16, ct_tag + n) == 1;
    EVP_CIPHER_CTX_free(c); EVP_CIPHER_free(ci);
    return ok;
}

/* Parameter and call-order handling: a refusal, never a success that
 * leaves state or output wrong. */
static void case_params(void) {
    static const unsigned char key[16] = "a GCM key, 16 b", iv[12] = {9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 0, 1},
                               aad[5] = {23, 3, 3, 0, 9}, pt[9] = "plaintext";
    unsigned char out[64], ref[64], tag[16];
    int l = 0;

    /* TLS13-KDF: an invalid mode, or a digest that is not a string, is refused */
    EVP_KDF *k = EVP_KDF_fetch(G, "TLS13-KDF", NULL);
    EVP_KDF_CTX *kc = k ? EVP_KDF_CTX_new(k) : NULL;
    OSSL_PARAM bad_mode[] = { OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_MODE, "EXPAND-ONLY", 0), OSSL_PARAM_construct_end() };
    int mode3 = 3;
    OSSL_PARAM bad_mode_int[] = { OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode3), OSSL_PARAM_construct_end() };
    unsigned char dn[] = "SHA256";
    OSSL_PARAM bad_digest[] = { OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_DIGEST, dn, 6), OSSL_PARAM_construct_end() };
    OSSL_PARAM sha1[] = { OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, "SHA1", 0), OSSL_PARAM_construct_end() };
    CHECK(kc && EVP_KDF_CTX_set_params(kc, bad_mode) != 1, "tls13-kdf: an unknown mode name is refused");
    CHECK(kc && EVP_KDF_CTX_set_params(kc, bad_mode_int) != 1, "tls13-kdf: mode 3 is refused");
    CHECK(kc && EVP_KDF_CTX_set_params(kc, bad_digest) != 1, "tls13-kdf: a digest given as an octet string is refused");
    CHECK(kc && EVP_KDF_CTX_set_params(kc, sha1) != 1, "tls13-kdf: SHA-1 is refused");
    EVP_KDF_CTX_free(kc); EVP_KDF_free(k);

    EVP_CIPHER *gcm = EVP_CIPHER_fetch(G, "AES-128-GCM", NULL);
    CHECK(default_gcm(key, iv, aad, 5, pt, 9, ref), "gcm reference: the default provider seals");

    /* AAD after the data is refused, encrypt and decrypt */
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    CHECK(EVP_EncryptInit_ex(c, gcm, NULL, key, iv) == 1 && EVP_EncryptUpdate(c, out, &l, pt, 9) == 1
          && EVP_EncryptUpdate(c, NULL, &l, aad, 5) != 1,
          "gcm: AAD after the data is refused (encrypt)");
    EVP_CIPHER_CTX_free(c);
    c = EVP_CIPHER_CTX_new();
    memcpy(tag, ref + 9, 16);
    CHECK(EVP_DecryptInit_ex(c, gcm, NULL, key, iv) == 1 && EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_TAG, 16, tag) == 1
          && EVP_DecryptUpdate(c, NULL, &l, aad, 5) == 1 && EVP_DecryptUpdate(c, out, &l, ref, 9) == 1
          && memcmp(out, pt, 9) == 0,
          "gcm: AAD, then the data, opens (tag set first)");
    CHECK(EVP_DecryptUpdate(c, NULL, &l, aad, 5) != 1, "gcm: AAD after the data is refused (decrypt, tag set first)");
    EVP_CIPHER_CTX_free(c);
    c = EVP_CIPHER_CTX_new();
    CHECK(EVP_DecryptInit_ex(c, gcm, NULL, key, iv) == 1 && EVP_DecryptUpdate(c, out, &l, ref, 9) == 1
          && EVP_DecryptUpdate(c, NULL, &l, aad, 5) != 1,
          "gcm: AAD after the data is refused (decrypt, tag set at the end)");
    EVP_CIPHER_CTX_free(c);

    /* EVP_Cipher (one-shot) binds AAD given before the data */
    c = EVP_CIPHER_CTX_new();
    CHECK(EVP_EncryptInit_ex(c, gcm, NULL, key, iv) == 1 && EVP_Cipher(c, NULL, aad, 5) >= 0
          && EVP_Cipher(c, out, pt, 9) == 9 && EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_GET_TAG, 16, out + 9) == 1
          && memcmp(out, ref, 25) == 0,
          "gcm EVP_Cipher: AAD is in the tag (matches the default provider)");
    CHECK(EVP_Cipher(c, NULL, aad, 5) < 0, "gcm EVP_Cipher: AAD after the data is refused");
    EVP_CIPHER_CTX_free(c);
    c = EVP_CIPHER_CTX_new();
    memcpy(tag, ref + 9, 16);
    CHECK(EVP_DecryptInit_ex(c, gcm, NULL, key, iv) == 1 && EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_TAG, 16, tag) == 1
          && EVP_Cipher(c, NULL, aad, 5) >= 0 && EVP_Cipher(c, out, ref, 9) == 9 && memcmp(out, pt, 9) == 0,
          "gcm EVP_Cipher: opens with the AAD");
    EVP_CIPHER_CTX_free(c);
    c = EVP_CIPHER_CTX_new();
    CHECK(EVP_DecryptInit_ex(c, gcm, NULL, key, iv) == 1 && EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_TAG, 16, tag) == 1
          && EVP_Cipher(c, out, ref, 9) < 0,
          "gcm EVP_Cipher: a tag over AAD does not open without it");
    EVP_CIPHER_CTX_free(c);

    /* IV queries: answered, or refused; never success over an unwritten buffer */
    c = EVP_CIPHER_CTX_new();
    unsigned char got[16] = {0};
    CHECK(EVP_EncryptInit_ex(c, gcm, NULL, key, iv) == 1 && EVP_CIPHER_CTX_get_updated_iv(c, got, 12) == 1
          && memcmp(got, iv, 12) == 0,
          "gcm: the IV query reports the nonce");
    unsigned char ivgen[12];
    OSSL_PARAM q[] = { OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TLS1_GET_IV_GEN, ivgen, sizeof ivgen), OSSL_PARAM_construct_end() };
    CHECK(EVP_CIPHER_CTX_get_params(c, q) != 1, "gcm: the TLS1 IV-generator query is refused");
    EVP_CIPHER_CTX_free(c);

    /* CBC: a copy keeps the buffered partial block; the IV query tracks chaining */
    static const unsigned char cbck[16] = "a CBC key, 16 b", cbciv[16] = "the CBC IV, 16b";
    unsigned char msg[20] = "twenty bytes, a b c", a[48], b[48];
    EVP_CIPHER *cbc = EVP_CIPHER_fetch(G, "AES-128-CBC", NULL), *dcbc = EVP_CIPHER_fetch(D, "AES-128-CBC", NULL);
    EVP_CIPHER_CTX *x = EVP_CIPHER_CTX_new(), *y = EVP_CIPHER_CTX_new(), *z = EVP_CIPHER_CTX_new();
    int la = 0, fa = 0, lb = 0, fb = 0;
    CHECK(cbc && dcbc && EVP_EncryptInit_ex(z, dcbc, NULL, cbck, cbciv) == 1 && EVP_EncryptUpdate(z, b, &lb, msg, 20) == 1
          && EVP_EncryptFinal_ex(z, b + lb, &fb) == 1
          && EVP_EncryptInit_ex(x, cbc, NULL, cbck, cbciv) == 1 && EVP_EncryptUpdate(x, a, &la, msg, 20) == 1
          && EVP_CIPHER_CTX_copy(y, x) == 1 && EVP_EncryptFinal_ex(y, a + la, &fa) == 1
          && la + fa == lb + fb && memcmp(a, b, la + fa) == 0,
          "cbc: a copy taken mid-message finishes with the buffered tail");
    CHECK(EVP_CIPHER_CTX_get_updated_iv(x, got, 16) == 1 && la == 16 && memcmp(got, a, 16) == 0
          && EVP_CIPHER_CTX_get_original_iv(x, got, 16) == 1 && memcmp(got, cbciv, 16) == 0,
          "cbc: the IV queries report the chaining IV and the IV as set");
    EVP_CIPHER_CTX_free(x); EVP_CIPHER_CTX_free(y); EVP_CIPHER_CTX_free(z);
    EVP_CIPHER_free(cbc); EVP_CIPHER_free(dcbc);

    /* a parameter list past the provider's bound is refused, not truncated */
    enum { N = 1100 };
    OSSL_PARAM *big = calloc(N + 1, sizeof *big);
    unsigned int tl = 16;
    for (int i = 0; big && i < N; i++) big[i] = OSSL_PARAM_construct_uint("unknown-param", &tl);
    c = EVP_CIPHER_CTX_new();
    CHECK(big && EVP_EncryptInit_ex(c, gcm, NULL, key, iv) == 1 && EVP_CIPHER_CTX_set_params(c, big) != 1,
          "params: a list longer than the provider's bound is refused");
    EVP_CIPHER_CTX_free(c); free(big);
    EVP_CIPHER_free(gcm);
}

static int kdf_set(const char *alg, const char *key, int octet, const char *val) {
    EVP_KDF *k = EVP_KDF_fetch(G, alg, NULL);
    EVP_KDF_CTX *kc = k ? EVP_KDF_CTX_new(k) : NULL;
    OSSL_PARAM p[] = { octet ? OSSL_PARAM_construct_octet_string(key, (void *)val, strlen(val))
                             : OSSL_PARAM_construct_utf8_string(key, (char *)val, 0),
                       OSSL_PARAM_construct_end() };
    int r = kc ? EVP_KDF_CTX_set_params(kc, p) : -1;
    EVP_KDF_CTX_free(kc); EVP_KDF_free(k);
    return r;
}

/* the IV queries in pointer form (EVP_CIPHER_CTX_iv and friends) */
static int iv_ptr(EVP_CIPHER_CTX *c, const char *which, unsigned char *got, size_t n) {
    void *ptr = NULL;
    OSSL_PARAM p[] = { OSSL_PARAM_construct_octet_ptr(which, &ptr, 16), OSSL_PARAM_construct_end() };
    if (EVP_CIPHER_CTX_get_params(c, p) != 1 || ptr == NULL) return 0;
    memcpy(got, ptr, n);
    return 1;
}

typedef uint64_t (*newctx_fn)(void *);
typedef int (*init_fn)(uint64_t, const unsigned char *, size_t, const unsigned char *, size_t, const OSSL_PARAM *);
typedef int (*update_fn)(uint64_t, unsigned char *, size_t *, size_t, const unsigned char *, size_t);
typedef void (*free_fn)(uint64_t);

static void case_params2(void) {
    static const unsigned char key[16] = "a GCM key, 16 b", iv[12] = {9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 0, 1},
                               aad[5] = {23, 3, 3, 0, 9}, pt[9] = "plaintext";
    unsigned char out[64], ref[64], got[16], dgot[16];
    int l = 0;

    /* HKDF and HMAC refuse what TLS13-KDF refuses; TLS13-KDF takes the digest aliases */
    CHECK(kdf_set("HKDF", OSSL_KDF_PARAM_MODE, 0, "EXPAND-ONLY") != 1, "hkdf: an unknown mode name is refused");
    CHECK(kdf_set("HKDF", OSSL_KDF_PARAM_DIGEST, 1, "SHA256") != 1, "hkdf: a digest given as an octet string is refused");
    CHECK(kdf_set("HKDF", OSSL_KDF_PARAM_DIGEST, 0, "SHA1") != 1, "hkdf: SHA-1 is refused");
    CHECK(kdf_set("HKDF", OSSL_KDF_PARAM_DIGEST, 0, "SHA2-256") == 1, "hkdf: SHA2-256 is accepted");
    CHECK(kdf_set("TLS13-KDF", OSSL_KDF_PARAM_DIGEST, 0, "SHA-256") == 1
          && kdf_set("TLS13-KDF", OSSL_KDF_PARAM_DIGEST, 0, "sha2-256") == 1
          && kdf_set("TLS13-KDF", OSSL_KDF_PARAM_DIGEST, 0, "SHA2-384") == 1,
          "tls13-kdf: the SHA-256 and SHA-384 aliases are accepted");
    CHECK(kdf_set("TLS13-KDF", OSSL_KDF_PARAM_DIGEST, 0, "SHA3-256") != 1
          && kdf_set("TLS13-KDF", OSSL_KDF_PARAM_DIGEST, 0, "SHA2-512") != 1,
          "tls13-kdf: digests other than SHA-256 and SHA-384 are refused");

    static const unsigned char mkey[32] = "an HMAC key of thirty-two bytes";
    EVP_MAC *mac = EVP_MAC_fetch(G, "HMAC", NULL);
    EVP_MAC_CTX *mc = mac ? EVP_MAC_CTX_new(mac) : NULL;
    unsigned char dn[] = "SHA256";
    OSSL_PARAM oct[] = { OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_DIGEST, dn, 6), OSSL_PARAM_construct_end() };
    OSSL_PARAM s1[] = { OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, "SHA1", 0), OSSL_PARAM_construct_end() };
    CHECK(mc && EVP_MAC_CTX_set_params(mc, oct) != 1, "hmac: a digest given as an octet string is refused (set_params)");
    CHECK(mc && EVP_MAC_init(mc, mkey, 32, oct) != 1, "hmac: a digest given as an octet string is refused (init)");
    CHECK(mc && EVP_MAC_CTX_set_params(mc, s1) != 1, "hmac: SHA-1 is refused");
    EVP_MAC_CTX_free(mc); EVP_MAC_free(mac);

    EVP_CIPHER *gcm = EVP_CIPHER_fetch(G, "AES-128-GCM", NULL), *dgcm = EVP_CIPHER_fetch(D, "AES-128-GCM", NULL);
    CHECK(default_gcm(key, iv, aad, 5, pt, 9, ref), "gcm reference: the default provider seals");

    /* AAD through EVP_Cipher after a buffered decrypt update is refused */
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    CHECK(EVP_DecryptInit_ex(c, gcm, NULL, key, iv) == 1 && EVP_DecryptUpdate(c, out, &l, ref, 9) == 1
          && EVP_Cipher(c, NULL, aad, 5) < 0,
          "gcm EVP_Cipher: AAD after a data update is refused");
    EVP_CIPHER_CTX_free(c);

    /* EVP_Cipher final after the data returns what the default provider returns */
    int rg = -2, rd = -2;
    c = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX *dc = EVP_CIPHER_CTX_new();
    if (EVP_EncryptInit_ex(c, gcm, NULL, key, iv) == 1 && EVP_Cipher(c, NULL, aad, 5) >= 0 && EVP_Cipher(c, out, pt, 9) == 9)
        rg = EVP_Cipher(c, NULL, NULL, 0);
    if (EVP_EncryptInit_ex(dc, dgcm, NULL, key, iv) == 1 && EVP_Cipher(dc, NULL, aad, 5) >= 0 && EVP_Cipher(dc, out, pt, 9) == 9)
        rd = EVP_Cipher(dc, NULL, NULL, 0);
    CHECK(rg == rd && rg >= 0, "gcm EVP_Cipher: final after the data succeeds as in the default provider (%d, %d)", rg, rd);
    EVP_CIPHER_CTX_free(c); EVP_CIPHER_CTX_free(dc);

    /* IV queries in pointer form match the default provider; a TLS 1.2 ctx has no IV to report */
    c = EVP_CIPHER_CTX_new(); dc = EVP_CIPHER_CTX_new();
    CHECK(EVP_EncryptInit_ex(c, gcm, NULL, key, iv) == 1 && EVP_EncryptInit_ex(dc, dgcm, NULL, key, iv) == 1
          && iv_ptr(c, OSSL_CIPHER_PARAM_IV, got, 12) && iv_ptr(dc, OSSL_CIPHER_PARAM_IV, dgot, 12)
          && memcmp(got, dgot, 12) == 0 && memcmp(got, iv, 12) == 0,
          "gcm: the IV query in pointer form matches the default provider");
    EVP_CIPHER_CTX_free(c); EVP_CIPHER_CTX_free(dc);
    c = tls12_ctx(gcm, key, 1);
    CHECK(c && EVP_CIPHER_CTX_get_updated_iv(c, got, 12) != 1 && !iv_ptr(c, OSSL_CIPHER_PARAM_UPDATED_IV, got, 12),
          "tls12 gcm: the IV queries are refused");
    EVP_CIPHER_CTX_free(c);

    static const unsigned char cbck[16] = "a CBC key, 16 b", cbciv[16] = "the CBC IV, 16b";
    unsigned char msg[20] = "twenty bytes, a b c", a[48], og[16], od[16];
    EVP_CIPHER *cbc = EVP_CIPHER_fetch(G, "AES-128-CBC", NULL), *dcbc = EVP_CIPHER_fetch(D, "AES-128-CBC", NULL);
    c = EVP_CIPHER_CTX_new(); dc = EVP_CIPHER_CTX_new();
    CHECK(cbc && dcbc && EVP_EncryptInit_ex(c, cbc, NULL, cbck, cbciv) == 1 && EVP_EncryptInit_ex(dc, dcbc, NULL, cbck, cbciv) == 1
          && EVP_EncryptUpdate(c, a, &l, msg, 20) == 1 && EVP_EncryptUpdate(dc, a, &l, msg, 20) == 1
          && iv_ptr(c, OSSL_CIPHER_PARAM_UPDATED_IV, got, 16) && iv_ptr(dc, OSSL_CIPHER_PARAM_UPDATED_IV, dgot, 16)
          && iv_ptr(c, OSSL_CIPHER_PARAM_IV, og, 16) && iv_ptr(dc, OSSL_CIPHER_PARAM_IV, od, 16)
          && memcmp(got, dgot, 16) == 0 && memcmp(og, od, 16) == 0 && memcmp(og, cbciv, 16) == 0,
          "cbc: the IV queries in pointer form match the default provider");
    EVP_CIPHER_CTX_free(c); EVP_CIPHER_CTX_free(dc);
    EVP_CIPHER_free(cbc); EVP_CIPHER_free(dcbc);

    /* An init refused for its key length leaves the ctx as it was: the
     * same key still continues its record sequence afterwards. EVP sizes
     * the key from the algorithm, so this calls the provider directly. */
    void *so = dlopen(so_path, RTLD_NOW | RTLD_NOLOAD);
    newctx_fn nw = so ? (newctx_fn)dlsym(so, "gofips_cipher128_newctx") : NULL;
    init_fn ei = so ? (init_fn)dlsym(so, "gofips_cipher_encrypt_init") : NULL;
    update_fn up = so ? (update_fn)dlsym(so, "gofips_cipher_update") : NULL;
    free_fn fr = so ? (free_fn)dlsym(so, "gofips_cipher_freectx") : NULL;
    CHECK(nw && ei && up && fr, "direct: the provider's cipher entry points resolve");
    if (nw && ei && up && fr) {
        static const unsigned char key32[32] = "a different key of 32 bytes ...";
        unsigned char iv2[12], ref2[64];
        size_t ol = 0;
        memcpy(iv2, iv, 12); iv2[11] ^= 1;
        uint64_t h = nw(NULL);
        int first = ei(h, key, 16, iv, 12, NULL) == 1 && up(h, NULL, &ol, 0, aad, 5) == 1
                    && up(h, out, &ol, sizeof out, pt, 9) == 1 && ol == 9 && memcmp(out, ref, 9) == 0;
        CHECK(first, "direct: a sealed record matches the default provider");
        CHECK(ei(h, key32, 32, iv2, 12, NULL) != 1, "direct: a 32-byte key on AES-128-GCM is refused");
        CHECK(default_gcm(key, iv2, aad, 5, pt, 9, ref2) && ei(h, key, 16, iv2, 12, NULL) == 1
              && up(h, NULL, &ol, 0, aad, 5) == 1 && up(h, out, &ol, sizeof out, pt, 9) == 1 && ol == 9
              && memcmp(out, ref2, 9) == 0,
              "direct: after the refused init, the same key seals its next record");
        fr(h);
    }
    if (so) dlclose(so);
    EVP_CIPHER_free(gcm); EVP_CIPHER_free(dgcm);
}

/* HMAC as a key and a signature (the TLS 1.3 PSK binder's form). */
static int hmac_sign(OSSL_LIB_CTX *L, const char *md, const unsigned char *key, size_t keylen,
                     const unsigned char *msg, size_t n, unsigned char *out, size_t *outlen) {
    EVP_PKEY *k = EVP_PKEY_new_raw_private_key_ex(L, "HMAC", NULL, key, keylen);
    EVP_MD_CTX *m = EVP_MD_CTX_new();
    int ok = k && m && EVP_DigestSignInit_ex(m, NULL, md, L, NULL, k, NULL) == 1
             && EVP_DigestSignUpdate(m, msg, n) == 1 && EVP_DigestSignFinal(m, out, outlen) == 1;
    EVP_MD_CTX_free(m);
    EVP_PKEY_free(k);
    return ok;
}

static void case_hmac_sig(void) {
    static const unsigned char key[32] = "an HMAC key of thirty-two bytes";
    unsigned char g[64], d[64];
    size_t gl = sizeof g, dl = sizeof d;
    CHECK(hmac_sign(G, "SHA2-256", key, 32, (const unsigned char *)"binder", 6, g, &gl)
          && hmac_sign(D, "SHA2-256", key, 32, (const unsigned char *)"binder", 6, d, &dl) && gl == dl && memcmp(g, d, gl) == 0,
          "hmac signature: matches the default provider");
    gl = sizeof g;
    CHECK(!hmac_sign(G, "SHA2-256", key, 13, (const unsigned char *)"x", 1, g, &gl), "hmac signature: a key under 112 bits is refused");
    gl = sizeof g;
    CHECK(!hmac_sign(G, "SHA1", key, 32, (const unsigned char *)"x", 1, g, &gl), "hmac signature: SHA-1 is refused");
    size_t big = (1 << 20) + 1;
    unsigned char *m = calloc(1, big);
    gl = sizeof g;
    CHECK(m && hmac_sign(G, "SHA2-256", key, 32, m, 1 << 20, g, &gl), "hmac signature: 1 MiB of input is signed");
    gl = sizeof g;
    CHECK(m && !hmac_sign(G, "SHA2-256", key, 32, m, big, g, &gl), "hmac signature: more than 1 MiB is refused");
    free(m);
}

static SSL *pair(SSL_CTX *cc, SSL_CTX *sc, SSL **sv) {
    SSL *cl = SSL_new(cc);
    *sv = SSL_new(sc);
    BIO *c2s_w, *c2s_r, *s2c_w, *s2c_r;
    BIO_new_bio_pair(&c2s_w, 1 << 18, &c2s_r, 1 << 18);
    BIO_new_bio_pair(&s2c_w, 1 << 18, &s2c_r, 1 << 18);
    SSL_set_bio(cl, s2c_r, c2s_w);
    SSL_set_bio(*sv, c2s_r, s2c_w);
    SSL_set_connect_state(cl);
    SSL_set_accept_state(*sv);
    return cl;
}

static void run_case(const char *label, OSSL_LIB_CTX *CL, OSSL_LIB_CTX *SV, const char *suite, int rsa,
                     const char *keypem, long keylen, const char *certpem, long certlen) {
    long ops0 = gofips_ops("cipher"), kdf0 = gofips_ops("kdf");
    SSL_CTX *cc = make_ctx(CL, 0, suite, NULL, 0, NULL, 0);
    SSL_CTX *sc = make_ctx(SV, 1, suite, keypem, keylen, certpem, certlen);
    if (!cc || !sc) { CHECK(0, "%s %s: context setup", label, suite); ERR_print_errors_fp(stdout); return; }
    SSL *sv, *cl = pair(cc, sc, &sv);
    int hs = pump_handshake(cl, sv);
    CHECK(hs, "%s %s: TLS 1.2 handshake completes", label, suite);
    if (!hs) { ERR_print_errors_fp(stdout); goto done; }
    CHECK(strcmp(SSL_get_cipher_name(cl), suite) == 0 && SSL_version(cl) == TLS1_2_VERSION
          && SSL_get_extms_support(cl) == 1,
          "%s %s: negotiated %s over %s with the extended master secret", label, suite, SSL_get_cipher_name(cl), SSL_get_version(cl));
    int r = exchange(cl, sv, 200, 1);
    CHECK(r == 400, "%s %s: 400 application records, both directions, sizes 1..16384, all intact (%d)", label, suite, r);
    CHECK(gofips_ops("cipher") - ops0 > 0 && gofips_ops("kdf") - kdf0 > 0,
          "%s %s: gofips served the record cipher and the TLS 1.2 KDF", label, suite);

    /* resumption with the session from this connection */
    SSL_SESSION *sess = SSL_get1_session(cl);
    SSL *sv2, *cl2 = pair(cc, sc, &sv2);
    SSL_set_session(cl2, sess);
    int hs2 = pump_handshake(cl2, sv2);
    CHECK(hs2 && SSL_session_reused(cl2) && exchange(cl2, sv2, 10, 9) == 20,
          "%s %s: session resumed, records intact", label, suite);
    SSL_SESSION_free(sess);
    SSL_free(cl2); SSL_free(sv2);
done:
    (void)rsa;
    SSL_free(cl); SSL_free(sv); SSL_CTX_free(cc); SSL_CTX_free(sc);
}

/* a handshake that must fail; set_opts adjusts one side */
static void must_fail(const char *what, OSSL_LIB_CTX *CL, OSSL_LIB_CTX *SV, const char *csuite, const char *ssuite,
                      uint64_t copts, uint64_t sopts, const char *keypem, long keylen, const char *certpem, long certlen) {
    SSL_CTX *cc = make_ctx(CL, 0, csuite, NULL, 0, NULL, 0);
    SSL_CTX *sc = make_ctx(SV, 1, ssuite, keypem, keylen, certpem, certlen);
    int hs = 0, ctxok = cc && sc;
    if (ctxok) {
        SSL_CTX_set_options(cc, copts);
        SSL_CTX_set_options(sc, sopts);
        SSL *sv, *cl = pair(cc, sc, &sv);
        hs = pump_handshake(cl, sv) && exchange(cl, sv, 1, 3) == 2;
        SSL_free(cl); SSL_free(sv);
    }
    CHECK(!hs, "refused: %s", what);
    ERR_clear_error();
    SSL_CTX_free(cc); SSL_CTX_free(sc);
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <dir containing gofips.so>\n", argv[0]); return 2; }
    D = OSSL_LIB_CTX_new(); G = OSSL_LIB_CTX_new();
    if (!OSSL_PROVIDER_load(D, "default")) { printf("default provider failed to load\n"); return 2; }
    OSSL_PROVIDER_set_default_search_path(G, argv[1]);
    snprintf(so_path, sizeof so_path, "%s/gofips.so", argv[1]);
    GP = OSSL_PROVIDER_load(G, "gofips");
    if (!GP || !OSSL_PROVIDER_load(G, "base")) { printf("gofips/base provider failed to load\n"); return 2; }

    case_prf();
    case_nonce();
    case_params();
    case_params2();
    case_hmac_sig();

    char *ek, *ec, *rk, *rc; long ekl, ecl, rkl, rcl;
    if (!make_identity_kind(0, &ek, &ekl, &ec, &ecl) || !make_identity_kind(1, &rk, &rkl, &rc, &rcl)) {
        printf("identity setup failed\n"); return 2;
    }
    const char *ecdsa[] = {"ECDHE-ECDSA-AES128-GCM-SHA256", "ECDHE-ECDSA-AES256-GCM-SHA384"};
    for (int s = 0; s < 2; s++) {
        run_case("gofips client -> default server:", G, D, ecdsa[s], 0, ek, ekl, ec, ecl);
        run_case("default client -> gofips server:", D, G, ecdsa[s], 0, ek, ekl, ec, ecl);
        run_case("gofips client -> gofips server: ", G, G, ecdsa[s], 0, ek, ekl, ec, ecl);
    }
    /* RSA certificates: gofips verifies RSA (it does not sign with it) */
    run_case("gofips client -> default RSA server:", G, D, "ECDHE-RSA-AES128-GCM-SHA256", 1, rk, rkl, rc, rcl);
    run_case("gofips client -> default RSA server:", G, D, "ECDHE-RSA-AES256-GCM-SHA384", 1, rk, rkl, rc, rcl);

    must_fail("a default server without the extended master secret (gofips client)", G, D,
              ecdsa[0], ecdsa[0], 0, SSL_OP_NO_EXTENDED_MASTER_SECRET, ek, ekl, ec, ecl);
    must_fail("a default client without the extended master secret (gofips server)", D, G,
              ecdsa[0], ecdsa[0], SSL_OP_NO_EXTENDED_MASTER_SECRET, 0, ek, ekl, ec, ecl);
    must_fail("a CBC cipher suite (gofips client)", G, D, "ECDHE-ECDSA-AES128-SHA256", "ECDHE-ECDSA-AES128-SHA256",
              0, 0, ek, ekl, ec, ecl);
    must_fail("a CBC cipher suite (gofips server)", D, G, "ECDHE-ECDSA-AES256-SHA384", "ECDHE-ECDSA-AES256-SHA384",
              0, 0, ek, ekl, ec, ecl);
    must_fail("ChaCha20-Poly1305 (gofips client)", G, D, "ECDHE-ECDSA-CHACHA20-POLY1305", "ECDHE-ECDSA-CHACHA20-POLY1305",
              0, 0, ek, ekl, ec, ecl);
    must_fail("RSA key exchange (gofips client)", G, D, "AES128-GCM-SHA256", "AES128-GCM-SHA256", 0, 0, rk, rkl, rc, rcl);

    printf("%s\n", fails ? "TLS12: FAILURES" : "TLS12: ALL PASS");
    return fails ? 1 : 0;
}
