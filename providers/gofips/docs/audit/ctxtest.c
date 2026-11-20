#include <stdio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
int main(void) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) { printf("SSL_CTX_new FAILED\n"); ERR_print_errors_fp(stderr); return 1; }
    printf("SSL_CTX_new OK (default cipher list constructed)\n");
    return 0;
}
