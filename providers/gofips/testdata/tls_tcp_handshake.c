/* tls_tcp_handshake.c: a TLS 1.3 connection over a real loopback TCP
 * socket, with gofips serving both the client and the server (E-22).
 *
 * The certificate and key are made with the default provider; every TLS
 * operation runs in a gofips-only library context.
 *
 * Build:  cc -o tls_tcp_handshake tls_tcp_handshake.c $(pkg-config --cflags --libs openssl) -lpthread
 * Run:    GODEBUG=fips140=on ./tls_tcp_handshake <dir containing gofips.so>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/provider.h>

static OSSL_LIB_CTX *D, *G;
static char *keypem, *certpem;
static long keylen, certlen;
static int listen_fd, server_ok;

static int make_identity(void) {
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
    char *d;
    BIO *b = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(b, k, NULL, NULL, 0, NULL, NULL);
    keylen = BIO_get_mem_data(b, &d); keypem = malloc(keylen); memcpy(keypem, d, keylen); BIO_free(b);
    b = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(b, x);
    certlen = BIO_get_mem_data(b, &d); certpem = malloc(certlen); memcpy(certpem, d, certlen); BIO_free(b);
    EVP_PKEY_free(k); X509_free(x);
    return 1;
}

static SSL_CTX *make_ctx(int server) {
    SSL_CTX *c = SSL_CTX_new_ex(G, NULL, server ? TLS_server_method() : TLS_client_method());
    if (!c) return NULL;
    SSL_CTX_set_min_proto_version(c, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(c, TLS1_3_VERSION);
    SSL_CTX_set_options(c, SSL_OP_NO_TICKET);
    SSL_CTX_set_num_tickets(c, 0);
    SSL_CTX_set_verify(c, SSL_VERIFY_NONE, NULL);
    /* gofips serves the AES-GCM suites and ECDSA P-256 only. */
    if (!SSL_CTX_set_ciphersuites(c, "TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256")) return NULL;
    if (!SSL_CTX_set1_groups_list(c, "P-256")) return NULL;
    if (!SSL_CTX_set1_sigalgs_list(c, "ecdsa_secp256r1_sha256")) return NULL;
    if (server) {
        BIO *b = BIO_new_mem_buf(certpem, (int)certlen);
        X509 *x = PEM_read_bio_X509(b, NULL, NULL, NULL); BIO_free(b);
        b = BIO_new_mem_buf(keypem, (int)keylen);
        EVP_PKEY *k = PEM_read_bio_PrivateKey_ex(b, NULL, NULL, NULL, G, NULL); BIO_free(b);
        if (!x || !k || SSL_CTX_use_certificate(c, x) != 1 || SSL_CTX_use_PrivateKey(c, k) != 1) return NULL;
        X509_free(x); EVP_PKEY_free(k);
    }
    return c;
}

static void *server(void *arg) {
    (void)arg;
    SSL_CTX *ctx = make_ctx(1);
    int fd = accept(listen_fd, NULL, NULL);
    if (!ctx || fd < 0) return NULL;
    SSL *s = SSL_new(ctx);
    SSL_set_fd(s, fd);
    if (SSL_accept(s) == 1) {
        printf("server: handshake ok tls=%s cipher=%s\n", SSL_get_version(s), SSL_get_cipher_name(s));
        char buf[64];
        int n = SSL_read(s, buf, sizeof(buf) - 1);
        if (n > 0) { buf[n] = 0; printf("server: read %d bytes: %s\n", n, buf); }
        SSL_write(s, "pong", 4);
        n = SSL_read(s, buf, sizeof(buf) - 1);
        if (n > 0) { buf[n] = 0; printf("server: read %d bytes (2nd): %s\n", n, buf); server_ok = 1; }
    } else {
        printf("server: handshake FAILED\n");
        ERR_print_errors_fp(stdout);
    }
    fflush(stdout);
    SSL_shutdown(s); SSL_free(s); close(fd); SSL_CTX_free(ctx);
    return NULL;
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <dir containing gofips.so>\n", argv[0]); return 2; }
    setvbuf(stdout, NULL, _IOLBF, 0);
    D = OSSL_LIB_CTX_new(); G = OSSL_LIB_CTX_new();
    if (!OSSL_PROVIDER_load(D, "default")) { printf("default provider failed to load\n"); return 2; }
    OSSL_PROVIDER_set_default_search_path(G, argv[1]);
    if (!OSSL_PROVIDER_load(G, "gofips") || !OSSL_PROVIDER_load(G, "base")) { printf("gofips/base provider failed to load\n"); return 2; }
    printf("gofips loaded\n");
    if (!make_identity()) { printf("identity setup failed\n"); return 2; }

    struct sockaddr_in a = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    socklen_t al = sizeof(a);
    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0 || bind(listen_fd, (struct sockaddr *)&a, sizeof(a)) != 0 || listen(listen_fd, 1) != 0
        || getsockname(listen_fd, (struct sockaddr *)&a, &al) != 0) { perror("listen"); return 2; }
    pthread_t t;
    pthread_create(&t, NULL, server, NULL);

    int ok = 0;
    SSL_CTX *ctx = make_ctx(0);
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (ctx && fd >= 0 && connect(fd, (struct sockaddr *)&a, sizeof(a)) == 0) {
        SSL *c = SSL_new(ctx);
        SSL_set_fd(c, fd);
        if (SSL_connect(c) == 1) {
            printf("client: handshake ok tls=%s cipher=%s\n", SSL_get_version(c), SSL_get_cipher_name(c));
            SSL_write(c, "ping-from-client", 16);
            char buf[16];
            int n = SSL_read(c, buf, sizeof(buf) - 1);
            if (n > 0) { buf[n] = 0; printf("client: read %d bytes: %s\n", n, buf); }
            SSL_write(c, "second-message", 14);
            ok = n == 4;
        } else {
            printf("client: handshake FAILED\n");
            ERR_print_errors_fp(stdout);
        }
        SSL_shutdown(c); SSL_free(c);
    }
    pthread_join(t, NULL);
    close(fd); close(listen_fd); SSL_CTX_free(ctx);
    printf(ok && server_ok ? "TLS TCP HANDSHAKE: PASS\n" : "TLS TCP HANDSHAKE: FAIL\n");
    return ok && server_ok ? 0 : 1;
}
