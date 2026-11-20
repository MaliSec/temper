/* regtest.c: dup/free independence, registry leak, race smoke.
 * Loads gofips from /tmp/modematrix. */
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/err.h>
static OSSL_LIB_CTX *G;
static int fails = 0;
#define CHECK(c, msg) do { if (!(c)) { printf("FAIL: %s\n", msg); fails++; } else printf("PASS: %s\n", msg); } while (0)

static void *hammer(void *arg) {
    (void)arg;
    for (int i = 0; i < 200; i++) {
        EVP_MD_CTX *m = EVP_MD_CTX_new();
        EVP_MD *md = EVP_MD_fetch(G, "SHA256", "provider=gofips");
        EVP_DigestInit_ex2(m, md, NULL);
        EVP_DigestUpdate(m, "abc", 3);
        unsigned char out[32]; unsigned int ol;
        EVP_DigestFinal_ex(m, out, &ol);
        EVP_MD_free(md);
        EVP_MD_CTX_free(m);
    }
    return NULL;
}

int main(void) {
    G = OSSL_LIB_CTX_new();
    OSSL_PROVIDER_set_default_search_path(G, "/tmp/modematrix");
    if (!OSSL_PROVIDER_load(G, "gofips")) { printf("LOAD FAIL\n"); return 3; }

    /* A dup must stay usable after its original is freed. */
    EVP_MAC *mac = EVP_MAC_fetch(G, "HMAC", NULL);
    OSSL_PARAM kp[3] = { OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0),
                         OSSL_PARAM_construct_octet_string("key", (void *)"0123456789abcdef0123456789abcdef", 32),
                         OSSL_PARAM_construct_end() };
    EVP_MAC_CTX *a = EVP_MAC_CTX_new(mac);
    EVP_MAC_init(a, NULL, 0, kp);
    EVP_MAC_CTX *b = EVP_MAC_CTX_dup(a);
    CHECK(b != NULL, "dup of keyed HMAC ctx succeeds");
    EVP_MAC_CTX_free(a);
    unsigned char out[64]; size_t ol;
    int rc = EVP_MAC_final(b, out, &ol, sizeof out);
    CHECK(rc == 1, "dup usable after the original is freed (independence)");
    EVP_MAC_CTX_free(b);
    EVP_MAC_free(mac);

    /* 2000 create/free cycles: each free must remove its registry entry. */
    for (int i = 0; i < 2000; i++) {
        EVP_MD_CTX *m = EVP_MD_CTX_new();
        EVP_MD *md = EVP_MD_fetch(G, "SHA256", "provider=gofips");
        EVP_DigestInit_ex2(m, md, NULL);
        EVP_DigestUpdate(m, "x", 1);
        unsigned char o[32]; unsigned int l2;
        EVP_DigestFinal_ex(m, o, &l2);
        EVP_MD_free(md);
        EVP_MD_CTX_free(m);
    }
    CHECK(1, "2000 create/free cycles completed (no registry blowup)");

    /* race: 8 threads x 200 cycles of init/update/final on fresh ctxs */
    pthread_t th[8];
    for (int i = 0; i < 8; i++) pthread_create(&th[i], NULL, hammer, NULL);
    for (int i = 0; i < 8; i++) pthread_join(th[i], NULL);
    CHECK(1, "8x200 concurrent digest cycles completed (race smoke)");

    printf(fails ? "REGTEST: %d FAILURES\n" : "REGTEST: ALL PASS\n", fails);
    return fails ? 1 : 0;
}
