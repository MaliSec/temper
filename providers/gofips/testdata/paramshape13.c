/* paramshape13.c - 13 NULL-data/short-buffer parameter shapes, each run
 * on gofips (G) and the default provider (D). A shape passes when both
 * calls return (a panic aborts before the final line) and gofips's rc,
 * return_size and buffer state match the default provider.
 *
 *   S01 keymgmt group-name read, NULL buffer, size 64 (typed GET)
 *   S02 keymgmt group-name read, truncated 5-byte buffer (typed GET)
 *   S03 keymgmt group-name read, NULL buffer, size 0 (size query)
 *   S04 HKDF set digest, NULL data
 *   S05 HKDF set digest, NULL data, size-0 query (return_size class)
 *   S06 HMAC set digest, NULL data
 *   S07 TLS13-KDF set digest, NULL data
 *   S08 EC keygen set group, NULL data
 *   S09 CBC ivlen read, NULL data (raw cipher get_params)
 *   S10 SHA-256 size read, NULL data (digest get_params)
 *   S11 HMAC key read, NULL data (getOctetParam class)
 *   S12 cipher get_ctx_params keylen, NULL data
 *   S13 HKDF get_ctx_params, NULL data (unknown-GET-key refusal)
 *
 * Run: cc -o paramshape13 paramshape13.c $(pkg-config --cflags --libs openssl)
 *      GODEBUG=fips140=on ./paramshape13 <dir-containing-gofips.so>
 * Exit status is the number of failures.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/kdf.h>
#include <openssl/err.h>

static OSSL_LIB_CTX *G, *D;
static int fails = 0;
#define CHECK(cond, ...) do { if (!(cond)) { printf("FAIL: "); printf(__VA_ARGS__); printf("\n"); fails++; } else { printf("PASS: "); printf(__VA_ARGS__); printf("\n"); } } while (0)

/* S01: default (3.5.6, 4.0.3) returns rc=1, need=10 (no NUL). */
static void s01(void) {
    size_t needG = 0, needD = 0;
    int rg = 0, rd = 0;
    EVP_PKEY *kg = EVP_PKEY_Q_keygen(G, NULL, "EC", "prime256v1");
    EVP_PKEY *kd = EVP_PKEY_Q_keygen(D, NULL, "EC", "prime256v1");
    if (kg) rg = EVP_PKEY_get_utf8_string_param(kg, OSSL_PKEY_PARAM_GROUP_NAME, NULL, 64, &needG);
    if (kd) rd = EVP_PKEY_get_utf8_string_param(kd, OSSL_PKEY_PARAM_GROUP_NAME, NULL, 64, &needD);
    CHECK(rg == 1 && rd == 1 && needG == needD,
          "S01 group read NULL/64: gofips rc=%d need=%zu, default rc=%d need=%zu",
          rg, needG, rd, needD);
    EVP_PKEY_free(kg); EVP_PKEY_free(kd);
}

/* S02: both refuse with the buffer untouched. The raw-layer return_size
 * is covered by ecboundary P3. */
static void s02(void) {
    char bufG[5], bufD[5];
    memset(bufG, 0x41, 5); memset(bufD, 0x41, 5);
    size_t needG = 0, needD = 0;
    int rg = 0, rd = 0;
    EVP_PKEY *kg = EVP_PKEY_Q_keygen(G, NULL, "EC", "prime256v1");
    EVP_PKEY *kd = EVP_PKEY_Q_keygen(D, NULL, "EC", "prime256v1");
    if (kg) rg = EVP_PKEY_get_utf8_string_param(kg, OSSL_PKEY_PARAM_GROUP_NAME, bufG, 5, &needG);
    if (kd) rd = EVP_PKEY_get_utf8_string_param(kd, OSSL_PKEY_PARAM_GROUP_NAME, bufD, 5, &needD);
    int untouched = memcmp(bufG, bufD, 5) == 0 && bufG[0] == 0x41;
    CHECK(rg == 0 && rd == 0 && untouched,
          "S02 group read 5-byte buffer: gofips rc=%d, default rc=%d, buffers untouched",
          rg, rd);
    EVP_PKEY_free(kg); EVP_PKEY_free(kd);
}

/* S03: both succeed with the needed size (10 for prime256v1). */
static void s03(void) {
    size_t needG = 0, needD = 0;
    int rg = 0, rd = 0;
    EVP_PKEY *kg = EVP_PKEY_Q_keygen(G, NULL, "EC", "prime256v1");
    EVP_PKEY *kd = EVP_PKEY_Q_keygen(D, NULL, "EC", "prime256v1");
    if (kg) rg = EVP_PKEY_get_utf8_string_param(kg, OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0, &needG);
    if (kd) rd = EVP_PKEY_get_utf8_string_param(kd, OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0, &needD);
    CHECK(rg == 1 && rd == 1 && needG == 10 && needD == 10,
          "S03 group NULL/0 query: gofips rc=%d need=%zu, default rc=%d need=%zu (both 10)",
          rg, needG, rd, needD);
    EVP_PKEY_free(kg); EVP_PKEY_free(kd);
}

/* S04/S05: both fail the whole set (rc=0). */
static void s045(int shape) {
    unsigned char ikm[22]; memset(ikm, 0x0b, 22);
    OSSL_PARAM pG[3], pD[3];
    int n = 0;
    pG[n] = (OSSL_PARAM){ OSSL_KDF_PARAM_DIGEST, OSSL_PARAM_UTF8_STRING, NULL, shape == 4 ? 16 : 0, 0 };
    pD[n] = pG[n]; n++;
    pG[n] = (OSSL_PARAM){ OSSL_KDF_PARAM_KEY, OSSL_PARAM_OCTET_STRING, ikm, sizeof ikm, 0 };
    pD[n] = pG[n]; n++;
    pG[n] = OSSL_PARAM_construct_end();
    pD[n] = OSSL_PARAM_construct_end();
    EVP_KDF *kg = EVP_KDF_fetch(G, "HKDF", NULL);
    EVP_KDF *kd = EVP_KDF_fetch(D, "HKDF", NULL);
    EVP_KDF_CTX *cg = EVP_KDF_CTX_new(kg), *cd = EVP_KDF_CTX_new(kd);
    int rg = EVP_KDF_CTX_set_params(cg, pG);
    int rd = EVP_KDF_CTX_set_params(cd, pD);
    CHECK(rg == 0 && rd == 0,
          "S%02d HKDF set digest NULL data (size %d): gofips rc=%d, default rc=%d (both refuse)",
          shape, shape == 4 ? 16 : 0, rg, rd);
    EVP_KDF_CTX_free(cg); EVP_KDF_CTX_free(cd);
    EVP_KDF_free(kg); EVP_KDF_free(kd);
}

/* S06: via EVP_MAC_init; both refuse. */
static void s06(void) {
    OSSL_PARAM pG[3], pD[3];
    int n = 0;
    pG[n] = (OSSL_PARAM){ OSSL_MAC_PARAM_DIGEST, OSSL_PARAM_UTF8_STRING, NULL, 16, 0 };
    pD[n] = pG[n]; n++;
    pG[n] = (OSSL_PARAM){ OSSL_MAC_PARAM_KEY, OSSL_PARAM_OCTET_STRING, (void *)"0123456789abcdef0123", 20, 0 };
    pD[n] = pG[n]; n++;
    pG[n] = OSSL_PARAM_construct_end();
    pD[n] = OSSL_PARAM_construct_end();
    EVP_MAC *mg = EVP_MAC_fetch(G, "HMAC", NULL);
    EVP_MAC *md = EVP_MAC_fetch(D, "HMAC", NULL);
    EVP_MAC_CTX *cg = EVP_MAC_CTX_new(mg), *cd = EVP_MAC_CTX_new(md);
    int rg = EVP_MAC_init(cg, NULL, 0, pG);
    int rd = EVP_MAC_init(cd, NULL, 0, pD);
    CHECK(rg == 0 && rd == 0,
          "S06 HMAC set digest NULL data: gofips rc=%d, default rc=%d (both refuse)",
          rg, rd);
    EVP_MAC_CTX_free(cg); EVP_MAC_CTX_free(cd);
    EVP_MAC_free(mg); EVP_MAC_free(md);
}

/* S07: both refuse. */
static void s07(void) {
    unsigned char ikm[32]; memset(ikm, 0x0c, 32);
    int mode = 2;
    OSSL_PARAM pG[4], pD[4];
    int n = 0;
    pG[n] = (OSSL_PARAM){ OSSL_KDF_PARAM_MODE, OSSL_PARAM_INTEGER, &mode, 4, 0 };
    pD[n] = pG[n]; n++;
    pG[n] = (OSSL_PARAM){ OSSL_KDF_PARAM_DIGEST, OSSL_PARAM_UTF8_STRING, NULL, 16, 0 };
    pD[n] = pG[n]; n++;
    pG[n] = (OSSL_PARAM){ OSSL_KDF_PARAM_KEY, OSSL_PARAM_OCTET_STRING, ikm, sizeof ikm, 0 };
    pD[n] = pG[n]; n++;
    pG[n] = OSSL_PARAM_construct_end();
    pD[n] = OSSL_PARAM_construct_end();
    EVP_KDF *kg = EVP_KDF_fetch(G, "TLS13-KDF", NULL);
    EVP_KDF *kd = EVP_KDF_fetch(D, "TLS13-KDF", NULL);
    if (!kg || !kd) { CHECK(0, "S07 TLS13-KDF fetch"); return; }
    EVP_KDF_CTX *cg = EVP_KDF_CTX_new(kg), *cd = EVP_KDF_CTX_new(kd);
    int rg = EVP_KDF_CTX_set_params(cg, pG);
    int rd = EVP_KDF_CTX_set_params(cd, pD);
    CHECK(rg == 0 && rd == 0,
          "S07 TLS13-KDF set digest NULL data: gofips rc=%d, default rc=%d (both refuse)",
          rg, rd);
    EVP_KDF_CTX_free(cg); EVP_KDF_CTX_free(cd);
    EVP_KDF_free(kg); EVP_KDF_free(kd);
}

/* S08: fromdata with a NULL-data group param; both refuse. */
static void s08(void) {
    OSSL_PARAM pG[2], pD[2];
    pG[0] = (OSSL_PARAM){ OSSL_PKEY_PARAM_GROUP_NAME, OSSL_PARAM_UTF8_STRING, NULL, 16, 0 };
    pD[0] = pG[0];
    pG[1] = OSSL_PARAM_construct_end();
    pD[1] = OSSL_PARAM_construct_end();
    EVP_PKEY_CTX *cg = EVP_PKEY_CTX_new_from_name(G, "EC", NULL);
    EVP_PKEY_CTX *cd = EVP_PKEY_CTX_new_from_name(D, "EC", NULL);
    EVP_PKEY *kg = NULL, *kd = NULL;
    EVP_PKEY_fromdata_init(cg); EVP_PKEY_fromdata_init(cd);
    int rg = EVP_PKEY_fromdata(cg, &kg, EVP_PKEY_PUBLIC_KEY, pG);
    int rd = EVP_PKEY_fromdata(cd, &kd, EVP_PKEY_PUBLIC_KEY, pD);
    CHECK(rg <= 0 && rd <= 0,
          "S08 EC fromdata NULL-data group: gofips rc=%d, default rc=%d (both refuse)",
          rg, rd);
    EVP_PKEY_free(kg); EVP_PKEY_free(kd);
    EVP_PKEY_CTX_free(cg); EVP_PKEY_CTX_free(cd);
}

/* S09: both succeed with return_size 8. */
static void s09(void) {
    EVP_CIPHER *cg = EVP_CIPHER_fetch(G, "AES-256-CBC", NULL);
    EVP_CIPHER *cd = EVP_CIPHER_fetch(D, "AES-256-CBC", NULL);
    if (!cg || !cd) { CHECK(0, "S09 AES-256-CBC fetch"); return; }
    OSSL_PARAM qG[2], qD[2];
    qG[0] = (OSSL_PARAM){ OSSL_CIPHER_PARAM_IVLEN, OSSL_PARAM_UNSIGNED_INTEGER, NULL, 8, 0 };
    qD[0] = qG[0];
    qG[1] = OSSL_PARAM_construct_end();
    qD[1] = OSSL_PARAM_construct_end();
    int rg = EVP_CIPHER_get_params(cg, qG);
    int rd = EVP_CIPHER_get_params(cd, qD);
    CHECK(rg == 1 && rd == 1 && qG[0].return_size == qD[0].return_size,
          "S09 CBC ivlen NULL data: gofips rc=%d rs=%zu, default rc=%d rs=%zu",
          rg, (size_t)qG[0].return_size, rd, (size_t)qD[0].return_size);
    EVP_CIPHER_free(cg); EVP_CIPHER_free(cd);
}

/* S10: both succeed with return_size 8. */
static void s10(void) {
    EVP_MD *mg = EVP_MD_fetch(G, "SHA256", NULL);
    EVP_MD *md = EVP_MD_fetch(D, "SHA256", NULL);
    if (!mg || !md) { CHECK(0, "S10 SHA256 fetch"); return; }
    OSSL_PARAM qG[2], qD[2];
    qG[0] = (OSSL_PARAM){ OSSL_DIGEST_PARAM_SIZE, OSSL_PARAM_UNSIGNED_INTEGER, NULL, 8, 0 };
    qD[0] = qG[0];
    qG[1] = OSSL_PARAM_construct_end();
    qD[1] = OSSL_PARAM_construct_end();
    int rg = EVP_MD_get_params(mg, qG);
    int rd = EVP_MD_get_params(md, qD);
    CHECK(rg == 1 && rd == 1 && qG[0].return_size == qD[0].return_size,
          "S10 SHA-256 size NULL data: gofips rc=%d rs=%zu, default rc=%d rs=%zu",
          rg, (size_t)qG[0].return_size, rd, (size_t)qD[0].return_size);
    EVP_MD_free(mg); EVP_MD_free(md);
}

/* S11: EVP_MAC_init with a NULL/0 key param; both refuse. */
static void s11(void) {
    OSSL_PARAM pG[3], pD[3];
    int n = 0;
    pG[n] = (OSSL_PARAM){ OSSL_MAC_PARAM_DIGEST, OSSL_PARAM_UTF8_STRING, "SHA256", 7, 0 };
    pD[n] = pG[n]; n++;
    pG[n] = (OSSL_PARAM){ OSSL_MAC_PARAM_KEY, OSSL_PARAM_OCTET_STRING, NULL, 0, 0 };
    pD[n] = pG[n]; n++;
    pG[n] = OSSL_PARAM_construct_end();
    pD[n] = OSSL_PARAM_construct_end();
    EVP_MAC *mg = EVP_MAC_fetch(G, "HMAC", NULL);
    EVP_MAC *md = EVP_MAC_fetch(D, "HMAC", NULL);
    EVP_MAC_CTX *cg = EVP_MAC_CTX_new(mg), *cd = EVP_MAC_CTX_new(md);
    int rg = EVP_MAC_init(cg, NULL, 0, pG);
    int rd = EVP_MAC_init(cd, NULL, 0, pD);
    CHECK(rg == 0 && rd == 0,
          "S11 HMAC key NULL/0: gofips rc=%d, default rc=%d (both refuse)",
          rg, rd);
    EVP_MAC_CTX_free(cg); EVP_MAC_CTX_free(cd);
    EVP_MAC_free(mg); EVP_MAC_free(md);
}

/* S12: both succeed with return_size 8. */
static void s12(void) {
    EVP_CIPHER *cg = EVP_CIPHER_fetch(G, "AES-256-GCM", NULL);
    EVP_CIPHER *cd = EVP_CIPHER_fetch(D, "AES-256-GCM", NULL);
    if (!cg || !cd) { CHECK(0, "S12 AES-256-GCM fetch"); return; }
    EVP_CIPHER_CTX *xg = EVP_CIPHER_CTX_new(), *xd = EVP_CIPHER_CTX_new();
    unsigned char key32[32]; memset(key32, 1, sizeof key32);
    unsigned char iv12[12]; memset(iv12, 9, sizeof iv12);
    EVP_EncryptInit_ex2(xg, cg, key32, iv12, NULL);
    EVP_EncryptInit_ex2(xd, cd, key32, iv12, NULL);
    OSSL_PARAM qG[2], qD[2];
    qG[0] = (OSSL_PARAM){ OSSL_CIPHER_PARAM_KEYLEN, OSSL_PARAM_UNSIGNED_INTEGER, NULL, 8, 0 };
    qD[0] = qG[0];
    qG[1] = OSSL_PARAM_construct_end();
    qD[1] = OSSL_PARAM_construct_end();
    int rg = EVP_CIPHER_CTX_get_params(xg, qG);
    int rd = EVP_CIPHER_CTX_get_params(xd, qD);
    CHECK(rg == 1 && rd == 1 && qG[0].return_size == qD[0].return_size,
          "S12 cipher keylen NULL data: gofips rc=%d rs=%zu, default rc=%d rs=%zu",
          rg, (size_t)qG[0].return_size, rd, (size_t)qD[0].return_size);
    EVP_CIPHER_CTX_free(xg); EVP_CIPHER_CTX_free(xd);
    EVP_CIPHER_free(cg); EVP_CIPHER_free(cd);
}

/* S13: HKDF get_ctx_params with NULL data on the DIGEST key. gofips must
 * return rc=0 on every ABI. The default provider varies:
 *   3.0/3.2: rc=-2   3.5 (3.5.8): rc=1, nothing set   4.0.3: rc=0
 * so the default side accepts any answer that sets nothing. */
static void s13(void) {
    EVP_KDF *kg = EVP_KDF_fetch(G, "HKDF", NULL);
    EVP_KDF *kd = EVP_KDF_fetch(D, "HKDF", NULL);
    EVP_KDF_CTX *cg = EVP_KDF_CTX_new(kg), *cd = EVP_KDF_CTX_new(kd);
    OSSL_PARAM pG[2], pD[2];
    pG[0] = (OSSL_PARAM){ OSSL_KDF_PARAM_DIGEST, OSSL_PARAM_UTF8_STRING, NULL, 0, 0 };
    pD[0] = pG[0];
    pG[1] = OSSL_PARAM_construct_end();
    pD[1] = OSSL_PARAM_construct_end();
    int rg = EVP_KDF_CTX_get_params(cg, pG);
    int rd = EVP_KDF_CTX_get_params(cd, pD);
    CHECK(rg == 0 && (rd <= 0 || (rd == 1 && pD[0].return_size == 0)),
          "S13 HKDF get DIGEST NULL/0: gofips rc=%d (refusal), default rc=%d (ABI-specific)",
          rg, rd);
    /* the SIZE key succeeds on both */
    pG[0] = (OSSL_PARAM){ OSSL_KDF_PARAM_SIZE, OSSL_PARAM_UNSIGNED_INTEGER, NULL, 8, 0 };
    pD[0] = pG[0];
    pG[1] = OSSL_PARAM_construct_end();
    pD[1] = OSSL_PARAM_construct_end();
    rg = EVP_KDF_CTX_get_params(cg, pG);
    rd = EVP_KDF_CTX_get_params(cd, pD);
    CHECK(rg == 1 && rd == 1 && pG[0].return_size == pD[0].return_size,
          "S13b HKDF get SIZE NULL/8: gofips rc=%d rs=%zu, default rc=%d rs=%zu",
          rg, (size_t)pG[0].return_size, rd, (size_t)pD[0].return_size);
    EVP_KDF_CTX_free(cg); EVP_KDF_CTX_free(cd);
    EVP_KDF_free(kg); EVP_KDF_free(kd);
}

int main(int argc, char **argv) {
    if (argc < 2) { printf("usage: paramshape13 <dir-containing-gofips.so>\n"); return 2; }
    D = OSSL_LIB_CTX_new();
    G = OSSL_LIB_CTX_new();
    if (!OSSL_PROVIDER_load(D, "default")) { printf("default load FAIL\n"); return 3; }
    OSSL_PROVIDER_set_default_search_path(G, argv[1]);
    if (!OSSL_PROVIDER_load(G, "gofips")) { printf("gofips load FAIL\n"); return 3; }

    s01(); s02(); s03();
    s045(4); s045(5);
    s06(); s07(); s08(); s09(); s10(); s11(); s12(); s13();

    printf(fails ? "PARAMSHAPE13: %d FAILURES\n" : "PARAMSHAPE13: ALL PASS (13 shapes x 2 providers, host alive)\n", fails);
    return fails ? 1 : 0;
}
