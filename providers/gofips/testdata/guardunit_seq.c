/* guardunit_seq.c: seal sequence for guardunit-attrib.sh.
 * Attempt 1 seals record 0 under a fresh key; attempt 2 reuses the same
 * nonce on the same ctx. On the gofips_debug build with GOFIPS_DEBUG=1,
 * stderr names the check that refused attempt 2.
 */
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
int main(int argc, char **argv) {
    if (argc < 2) return 2;
    OSSL_LIB_CTX *G = OSSL_LIB_CTX_new();
    OSSL_PROVIDER_set_default_search_path(G, argv[1]);
    if (!OSSL_PROVIDER_load(G, "gofips")) return 3;
    EVP_CIPHER *c = EVP_CIPHER_fetch(G, "AES-256-GCM", NULL);
    unsigned char key[32], nonce[12] = {9,9,9,9,9,9,9,9,9,9,9,9}, ct[64];
    for (int i = 0; i < 32; i++) key[i] = (unsigned char)(i + 1);
    EVP_CIPHER_CTX *x = EVP_CIPHER_CTX_new();
    if (!EVP_EncryptInit_ex2(x, c, key, NULL, NULL)) return 4;
    for (int i = 0; i < 2; i++) {
        int l = 0;
        unsigned char pt[16]; memset(pt, 'P', 16);
        int rc = EVP_EncryptInit_ex2(x, NULL, NULL, nonce, NULL) &&
                 EVP_EncryptUpdate(x, ct, &l, pt, 16);
        printf("attempt %d rc=%d\n", i + 1, rc);
    }
    EVP_CIPHER_CTX_free(x);
    return 0;
}
