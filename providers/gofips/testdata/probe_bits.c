/* probe_bits.c - return_size of NULL-data unsigned-integer GETs,
 * gofips (G) vs. the default provider (D).
 *
 * The default reports the value's natural size:
 *   - 4 for int-typed values: keymgmt bits, security-bits, max-size;
 *   - 8 for size_t-typed values: digest size/block-size, cipher
 *     block-size/ivlen/keylen, KDF size.
 * gofips must match each key. The 4-byte buffered write is also checked:
 * value written, return_size = data_size.
 *
 * Run: cc -o probe_bits probe_bits.c $(pkg-config --cflags --libs openssl)
 *      GOFIPS140=v1.0.0 GODEBUG=fips140=on OPENSSL_CONF=<conf> \
 *        ./probe_bits <dir-containing-gofips.so>
 * Exit status is the number of failures.
 */
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>

static OSSL_LIB_CTX *G, *D;
static int fails = 0;
#define CHECK(cond, ...) do { if (!(cond)) { printf("FAIL: "); printf(__VA_ARGS__); printf("\n"); fails++; } else { printf("PASS: "); printf(__VA_ARGS__); printf("\n"); } } while (0)

/* NULL-data size probe via raw keymgmt get_params */
static void bitsprobe(const char *key, int which, int *rc, size_t *rs) {
    OSSL_LIB_CTX *L = which ? D : G;
    EVP_PKEY *k = EVP_PKEY_Q_keygen(L, NULL, "EC", "prime256v1");
    if (!k) { *rc = -1; *rs = 0; return; }
    OSSL_PARAM q[2];
    q[0].key = key;
    q[0].data_type = OSSL_PARAM_UNSIGNED_INTEGER;
    q[0].data = NULL;
    q[0].data_size = 0;
    q[0].return_size = 0;
    q[1] = OSSL_PARAM_construct_end();
    *rc = EVP_PKEY_get_params(k, q);
    *rs = (size_t)q[0].return_size;
    EVP_PKEY_free(k);
}

/* 4-byte buffer write probe via raw keymgmt get_params */
static void bitsbuf4(const char *key, int which, int *rc, unsigned int *val, size_t *rs) {
    OSSL_LIB_CTX *L = which ? D : G;
    EVP_PKEY *k = EVP_PKEY_Q_keygen(L, NULL, "EC", "prime256v1");
    if (!k) { *rc = -1; *rs = 0; return; }
    unsigned int v = 0xEEEE;
    OSSL_PARAM q[2];
    q[0].key = key;
    q[0].data_type = OSSL_PARAM_UNSIGNED_INTEGER;
    q[0].data = &v;
    q[0].data_size = 4;
    q[0].return_size = 0;
    q[1] = OSSL_PARAM_construct_end();
    *rc = EVP_PKEY_get_params(k, q);
    *val = v;
    *rs = (size_t)q[0].return_size;
    EVP_PKEY_free(k);
}

static void cipherNullR(const char *side, const char *ciph, const char *key, int expect) {
    OSSL_LIB_CTX *L = strcmp(side, "gofips") == 0 ? G : D;
    EVP_CIPHER *c = EVP_CIPHER_fetch(L, ciph, NULL);
    if (!c) { CHECK(0, "%s %s fetch", side, ciph); return; }
    OSSL_PARAM q[2];
    q[0].key = key; q[0].data_type = OSSL_PARAM_UNSIGNED_INTEGER;
    q[0].data = NULL; q[0].data_size = 0; q[0].return_size = 0;
    q[1] = OSSL_PARAM_construct_end();
    int rc = EVP_CIPHER_get_params(c, q);
    CHECK(rc == 1 && (size_t)q[0].return_size == (size_t)expect,
          "%s %s %s NULL rs=%zu (expect %d)", side, ciph, key,
          (size_t)q[0].return_size, expect);
    EVP_CIPHER_free(c);
}

static void digestNullR(const char *side, const char *key, int expect) {
    OSSL_LIB_CTX *L = strcmp(side, "gofips") == 0 ? G : D;
    EVP_MD *m = EVP_MD_fetch(L, "SHA256", NULL);
    if (!m) { CHECK(0, "%s SHA256 fetch", side); return; }
    OSSL_PARAM q[2];
    q[0].key = key; q[0].data_type = OSSL_PARAM_UNSIGNED_INTEGER;
    q[0].data = NULL; q[0].data_size = 0; q[0].return_size = 0;
    q[1] = OSSL_PARAM_construct_end();
    int rc = EVP_MD_get_params(m, q);
    CHECK(rc == 1 && (size_t)q[0].return_size == (size_t)expect,
          "%s digest %s NULL rs=%zu (expect %d)", side, key,
          (size_t)q[0].return_size, expect);
    EVP_MD_free(m);
}

static void kdfNullR(const char *side, const char *kdf, const char *key, int expect) {
    OSSL_LIB_CTX *L = strcmp(side, "gofips") == 0 ? G : D;
    EVP_KDF *k = EVP_KDF_fetch(L, kdf, NULL);
    if (!k) { CHECK(0, "%s %s fetch", side, kdf); return; }
    EVP_KDF_CTX *c = EVP_KDF_CTX_new(k);
    OSSL_PARAM q[2];
    q[0].key = key; q[0].data_type = OSSL_PARAM_UNSIGNED_INTEGER;
    q[0].data = NULL; q[0].data_size = 0; q[0].return_size = 0;
    q[1] = OSSL_PARAM_construct_end();
    int rc = EVP_KDF_CTX_get_params(c, q);
    CHECK(rc == 1 && (size_t)q[0].return_size == (size_t)expect,
          "%s %s %s NULL rs=%zu (expect %d)", side, kdf, key,
          (size_t)q[0].return_size, expect);
    EVP_KDF_CTX_free(c); EVP_KDF_free(k);
}

int main(int argc, char **argv) {
    if (argc < 2) { printf("usage: probe_bits <dir-containing-gofips.so>\n"); return 2; }
    D = OSSL_LIB_CTX_new();
    G = OSSL_LIB_CTX_new();
    if (!OSSL_PROVIDER_load(D, "default")) { printf("default load FAIL\n"); return 3; }
    OSSL_PROVIDER_set_default_search_path(G, argv[1]);
    if (!OSSL_PROVIDER_load(G, "gofips")) { printf("gofips load FAIL\n"); return 3; }

    int rG, rD; size_t sG, sD;

    /* ---- int-typed: both report 4 ---- */
    bitsprobe(OSSL_PKEY_PARAM_BITS, 0, &rG, &sG);
    bitsprobe(OSSL_PKEY_PARAM_BITS, 1, &rD, &sD);
    CHECK(rG == 1 && rD == 1 && sG == 4 && sD == 4,
          "BITS NULL rs: gofips=%zu default=%zu (both 4)", sG, sD);

    bitsprobe(OSSL_PKEY_PARAM_SECURITY_BITS, 0, &rG, &sG);
    bitsprobe(OSSL_PKEY_PARAM_SECURITY_BITS, 1, &rD, &sD);
    CHECK(rG == 1 && rD == 1 && sG == 4 && sD == 4,
          "SECURITY_BITS NULL rs: gofips=%zu default=%zu (both 4)", sG, sD);

    bitsprobe(OSSL_PKEY_PARAM_MAX_SIZE, 0, &rG, &sG);
    bitsprobe(OSSL_PKEY_PARAM_MAX_SIZE, 1, &rD, &sD);
    CHECK(rG == 1 && rD == 1 && sG == 4 && sD == 4,
          "MAX_SIZE NULL rs: gofips=%zu default=%zu (both 4)", sG, sD);

    /* ---- size_t-typed: both report 8 ---- */
    bitsprobe(OSSL_PKEY_PARAM_MAX_SIZE, 0, &rG, &sG); /* result unused */
    cipherNullR("gofips", "AES-256-CBC", OSSL_CIPHER_PARAM_IVLEN, 8);
    cipherNullR("default", "AES-256-CBC", OSSL_CIPHER_PARAM_IVLEN, 8);
    cipherNullR("gofips", "AES-256-CBC", OSSL_CIPHER_PARAM_KEYLEN, 8);
    cipherNullR("default", "AES-256-CBC", OSSL_CIPHER_PARAM_KEYLEN, 8);
    cipherNullR("gofips", "AES-256-CBC", OSSL_CIPHER_PARAM_BLOCK_SIZE, 8);
    cipherNullR("default", "AES-256-CBC", OSSL_CIPHER_PARAM_BLOCK_SIZE, 8);
    cipherNullR("gofips", "AES-256-GCM", OSSL_CIPHER_PARAM_KEYLEN, 8);
    cipherNullR("default", "AES-256-GCM", OSSL_CIPHER_PARAM_KEYLEN, 8);
    digestNullR("gofips", OSSL_DIGEST_PARAM_SIZE, 8);
    digestNullR("default", OSSL_DIGEST_PARAM_SIZE, 8);
    digestNullR("gofips", OSSL_DIGEST_PARAM_BLOCK_SIZE, 8);
    digestNullR("default", OSSL_DIGEST_PARAM_BLOCK_SIZE, 8);
    kdfNullR("gofips", "HKDF", OSSL_KDF_PARAM_SIZE, 8);
    kdfNullR("default", "HKDF", OSSL_KDF_PARAM_SIZE, 8);

    /* ---- buffered write: value written, rs = data_size ---- */
    bitsbuf4(OSSL_PKEY_PARAM_BITS, 0, &rG, &(unsigned int){0}, &sG);
    {
        unsigned int vG = 0, vD = 0;
        bitsbuf4(OSSL_PKEY_PARAM_BITS, 0, &rG, &vG, &sG);
        bitsbuf4(OSSL_PKEY_PARAM_BITS, 1, &rD, &vD, &sD);
        CHECK(rG == 1 && rD == 1 && vG == vD && vG == 256 && sG == 4 && sD == 4,
              "BITS 4B buf: gofips rc=%d val=%u rs=%zu, default rc=%d val=%u rs=%zu",
              rG, vG, sG, rD, vD, sD);
    }

    printf(fails ? "PROBE_BITS: %d FAILURES\n" : "PROBE_BITS: ALL PASS\n", fails);
    return fails ? 1 : 0;
}
