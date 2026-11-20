/* tls13_handshake.c: TLS 1.3 connections through libssl with gofips on
 * one or both ends and the default provider as the other peer.
 *
 * End-to-end check of the TLS 1.3 GCM path (gcm_tls13.go): libssl
 * computes each record nonce, and the Go module's TLS 1.3 GCM enforces
 * the counter.
 *
 * For each pairing and cipher suite it:
 *   1. completes a handshake over an in-memory transport,
 *   2. sends records of many sizes in both directions and checks every byte,
 *   3. forces a KeyUpdate (new record keys) and repeats,
 *   4. reports how many cipher operations the gofips provider served.
 *
 * Build:  cc -o tls13_handshake tls13_handshake.c $(pkg-config --cflags --libs openssl)
 * Run:    GODEBUG=fips140=on ./tls13_handshake <dir containing gofips.so>
 */
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

static OSSL_LIB_CTX *D, *G;
static OSSL_PROVIDER *GP;
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

/* an ECDSA P-256 key and a self-signed certificate, made with the default provider */
static int make_identity(char **keypem, long *keylen, char **certpem, long *certlen) {
    EVP_PKEY *k = EVP_PKEY_Q_keygen(D, NULL, "EC", "prime256v1");
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
    SSL_CTX_set_min_proto_version(c, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(c, TLS1_3_VERSION);
    SSL_CTX_set_options(c, SSL_OP_NO_TICKET);
    SSL_CTX_set_num_tickets(c, 0);
    if (!SSL_CTX_set_ciphersuites(c, suite)) return NULL;
    if (!SSL_CTX_set1_groups_list(c, "secp256r1")) return NULL;
    if (!SSL_CTX_set1_sigalgs_list(c, "ecdsa_secp256r1_sha256")) return NULL;
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

static void run_case(const char *label, OSSL_LIB_CTX *CL, OSSL_LIB_CTX *SV, const char *suite,
                     const char *keypem, long keylen, const char *certpem, long certlen) {
    long ops0 = gofips_cipher_ops();
    SSL_CTX *cc = make_ctx(CL, 0, suite, NULL, 0, NULL, 0);
    SSL_CTX *sc = make_ctx(SV, 1, suite, keypem, keylen, certpem, certlen);
    if (!cc || !sc) { CHECK(0, "%s %s: context setup", label, suite); ERR_print_errors_fp(stdout); return; }
    SSL *cl = SSL_new(cc), *sv = SSL_new(sc);
    BIO *c2s_w, *c2s_r, *s2c_w, *s2c_r;
    BIO_new_bio_pair(&c2s_w, 1 << 18, &c2s_r, 1 << 18);
    BIO_new_bio_pair(&s2c_w, 1 << 18, &s2c_r, 1 << 18);
    SSL_set_bio(cl, s2c_r, c2s_w);
    SSL_set_bio(sv, c2s_r, s2c_w);
    SSL_set_connect_state(cl);
    SSL_set_accept_state(sv);

    int hs = pump_handshake(cl, sv);
    CHECK(hs, "%s %s: handshake completes", label, suite);
    if (!hs) { ERR_print_errors_fp(stdout); goto done; }
    CHECK(strcmp(SSL_get_cipher_name(cl), suite) == 0 && SSL_version(cl) == TLS1_3_VERSION,
          "%s %s: negotiated %s over %s", label, suite, SSL_get_cipher_name(cl), SSL_get_version(cl));

    int r1 = exchange(cl, sv, 200, 1);
    CHECK(r1 == 400, "%s %s: 400 application records, both directions, sizes 1..16384, all intact (%d)", label, suite, r1);

    /* new record keys in both directions, then keep going */
    int ku = SSL_key_update(cl, SSL_KEY_UPDATE_REQUESTED);
    int w1 = send_check(cl, sv, 100, 9001), w2 = send_check(sv, cl, 100, 9002);
    CHECK(ku == 1 && w1 && w2, "%s %s: KeyUpdate accepted and traffic continues under the new keys", label, suite);
    int r2 = exchange(cl, sv, 100, 5000);
    CHECK(r2 == 200, "%s %s: 200 more records after the key change, all intact (%d)", label, suite, r2);
    if (r1 != 400 || r2 != 200 || !w1 || !w2) ERR_print_errors_fp(stdout);
done:
    /* Every case has a gofips side, so its record protection ran in gofips. */
    if (hs) CHECK(gofips_cipher_ops() - ops0 > 0, "%s %s: gofips served the record cipher (%ld operations)",
                  label, suite, gofips_cipher_ops() - ops0);
    SSL_free(cl); SSL_free(sv); SSL_CTX_free(cc); SSL_CTX_free(sc);
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <dir containing gofips.so>\n", argv[0]); return 2; }
    D = OSSL_LIB_CTX_new(); G = OSSL_LIB_CTX_new();
    if (!OSSL_PROVIDER_load(D, "default")) { printf("default provider failed to load\n"); return 2; }
    OSSL_PROVIDER_set_default_search_path(G, argv[1]);
    GP = OSSL_PROVIDER_load(G, "gofips");
    /* "base" carries encoders/decoders only (no cryptographic algorithms) */
    if (!GP || !OSSL_PROVIDER_load(G, "base")) { printf("gofips/base provider failed to load\n"); return 2; }

    char *keypem, *certpem; long keylen, certlen;
    if (!make_identity(&keypem, &keylen, &certpem, &certlen)) { printf("identity setup failed\n"); return 2; }

    const char *suites[] = {"TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256"};
    for (int s = 0; s < 2; s++) {
        run_case("gofips client -> default server:", G, D, suites[s], keypem, keylen, certpem, certlen);
        run_case("default client -> gofips server:", D, G, suites[s], keypem, keylen, certpem, certlen);
        run_case("gofips client -> gofips server: ", G, G, suites[s], keypem, keylen, certpem, certlen);
    }
    printf("%s\n", fails ? "TLS13 HANDSHAKE: FAILURES" : "TLS13 HANDSHAKE: ALL PASS");
    return fails ? 1 : 0;
}
