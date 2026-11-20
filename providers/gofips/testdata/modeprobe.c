/* modeprobe.c: loader probe for mode-matrix.sh. Loads gofips from the
 * directory in argv[1] and reports LOADED or refused.
 */
#include <stdio.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/provider.h>
int main(int argc, char **argv) {
    OSSL_LIB_CTX *G = OSSL_LIB_CTX_new();
    OSSL_PROVIDER_set_default_search_path(G, argv[1]);
    OSSL_PROVIDER *p = OSSL_PROVIDER_load(G, "gofips");
    printf("load=%s\n", p ? "LOADED" : "refused");
    return p ? 0 : 2;
}
