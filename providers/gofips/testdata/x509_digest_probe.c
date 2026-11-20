/*
 * x509_digest_probe.c - X509_digest(SHA-256) under a gofips-only config.
 *
 * Certificate parsing is core code; the digest must come from gofips.
 * The probe checks the digest against argv[2] and that default/legacy
 * algorithms are unfetchable. run-x509-digest.sh adds GOFIPS_DEBUG=1 to
 * show the digest ran through gofips.
 *
 * Usage: x509_digest_probe <cert.pem> <expected-sha256-hex>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/provider.h>
#include <openssl/evp.h>

static int fail(const char *msg) {
    fprintf(stderr, "FAIL: %s\n", msg);
    ERR_print_errors_fp(stderr);
    return 1;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <cert.pem> <expected-sha256-hex>\n", argv[0]);
        return 2;
    }
    FILE *f = fopen(argv[1], "r");
    if (!f) return fail("cannot open cert");
    X509 *cert = PEM_read_X509(f, NULL, NULL, NULL);
    fclose(f);
    if (!cert) return fail("PEM_read_X509 failed");

    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int mdlen = 0;
    if (!X509_digest(cert, EVP_sha256(), md, &mdlen))
        return fail("X509_digest(sha256) failed");

    char hex[EVP_MAX_MD_SIZE * 2 + 1];
    for (unsigned int i = 0; i < mdlen; i++)
        sprintf(hex + 2 * i, "%02x", md[i]);
    printf("X509-SHA256 %s\n", hex);

    if (strcmp(hex, argv[2]) != 0) {
        fprintf(stderr, "expected %s\n", argv[2]);
        return fail("digest mismatch");
    }
    printf("PASS: digest matches expected value\n");

    /* Exclusivity is tested by fetch, not OSSL_PROVIDER_load("default"),
     * which would activate the built-in provider. MD5 exists only in
     * default/legacy. */
    EVP_MD *md5 = EVP_MD_fetch(NULL, "MD5", NULL);
    if (md5) {
        printf("FAIL: MD5 fetchable (default/legacy provider present, exclusivity violated)\n");
        return 1;
    }
    printf("PASS: MD5 not fetchable (default/legacy absent)\n");
    EVP_MD *sha256 = EVP_MD_fetch(NULL, "SHA256", NULL);
    if (!sha256) {
        printf("FAIL: SHA256 not fetchable (gofips not serving digests)\n");
        return 1;
    }
    EVP_MD_free(sha256);
    printf("PASS: SHA256 fetchable (gofips serving)\n");

    printf("X509-DIGEST-PROBE-OK\n");
    return 0;
}
