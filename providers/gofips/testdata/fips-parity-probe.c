/* fips-parity-probe.c (E-36): checks whether the OpenSSL FIPS provider
 * behaves like the default provider on the legacy-ctor NULL-propq EC
 * routing decision that gofips cannot intercept (audit page 06).
 *
 * Loads fips.so (from OPENSSL_MODULES) and base, no default provider,
 * generates a P-256 key through fips, then checks:
 *   1. which provider a NULL-propq EC keymgmt fetch resolves to;
 *   2. legacy-ctor ECDH derive and DigestSign succeed;
 *   3. gofips, loaded alongside, counts none of that work.
 *
 * Build: cc -o fips-parity-probe fips-parity-probe.c \
 *           $(pkg-config --cflags --libs openssl)
 * Control: add -DPARITY_PROVIDER='"default"' to run the same checks with
 *          the default provider in place of fips.
 * Run:   OPENSSL_MODULES=<dir-with-genuine-fips.so> \
 *          ./fips-parity-probe <dir-containing-gofips.so>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

#ifndef PARITY_PROVIDER
#define PARITY_PROVIDER "fips"
#define PARITY_LABEL "genuine fips"
#else
#define PARITY_LABEL PARITY_PROVIDER
#endif

static int fails = 0;
#define CHECK(c, msg) do { if (c) printf("PASS: %s\n", msg); \
    else { printf("FAIL: %s\n", msg); fails++; } } while (0)

static OSSL_PROVIDER *gprov = NULL;
static int gofipsOps(unsigned long *ecdh, unsigned long *ecdsa) {
    if (!gprov) return 0;
    char *ptr = NULL;
    OSSL_PARAM rp[2];
    rp[0] = OSSL_PARAM_construct_utf8_ptr("temperfips-ops", &ptr, 0);
    rp[1] = OSSL_PARAM_construct_end();
    if (OSSL_PROVIDER_get_params(gprov, rp) != 1 || ptr == NULL) return 0;
    char *v;
    if (ecdh && (v = strstr(ptr, "\"ecdh\"")) != NULL) *ecdh = strtoul(v + 7, NULL, 10);
    if (ecdsa && (v = strstr(ptr, "\"ecdsa\"")) != NULL) *ecdsa = strtoul(v + 8, NULL, 10);
    return 1;
}

int main(int argc, char **argv) {
    const char *so = argc > 1 ? argv[1] : getenv("GOFIPS_SO");
    if (!so) so = ".";

    OSSL_PROVIDER *f = OSSL_PROVIDER_load(NULL, PARITY_PROVIDER);
    CHECK(f != NULL, PARITY_LABEL " provider loads");
    OSSL_PROVIDER *b = OSSL_PROVIDER_load(NULL, "base");
    CHECK(b != NULL, "base provider loads (encoders/decoders)");
    if (!f || !b) return 1;
    const char *fname = NULL, *fver = NULL;
    OSSL_PARAM fr[3];
    fr[0] = OSSL_PARAM_construct_utf8_ptr(OSSL_PROV_PARAM_NAME, (char **)&fname, 0);
    fr[1] = OSSL_PARAM_construct_utf8_ptr(OSSL_PROV_PARAM_VERSION, (char **)&fver, 0);
    fr[2] = OSSL_PARAM_construct_end();
    OSSL_PROVIDER_get_params(f, fr);
    printf(PARITY_PROVIDER " provider under test: name=%s version=%s\n",
           fname ? fname : "(null)", fver ? fver : "(null)");

    /* argv[1]/GOFIPS_SO is the directory holding gofips.so. */
    OSSL_LIB_CTX *dummy = OSSL_LIB_CTX_new();
    OSSL_PROVIDER_set_default_search_path(NULL, so);
    (void)dummy;
    gprov = OSSL_PROVIDER_load(NULL, "gofips");
    printf("gofips loaded alongside: %s\n", gprov ? "yes" : "no");
    if (!gprov) return 1;

    unsigned long e0 = 0, s0 = 0;
    gofipsOps(&e0, &s0);

    EVP_PKEY_CTX *gctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", "provider=" PARITY_PROVIDER);
    CHECK(gctx != NULL, "EC keymgmt fetch with propq provider=" PARITY_PROVIDER);
    if (!gctx) return 1;
    EVP_PKEY_keygen_init(gctx);
    OSSL_PARAM gp[2];
    char group[] = "prime256v1";
    gp[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, group, 0);
    gp[1] = OSSL_PARAM_construct_end();
    EVP_PKEY_CTX_set_params(gctx, gp);
    EVP_PKEY *pk = NULL;
    int r = EVP_PKEY_generate(gctx, &pk);
    CHECK(r == 1 && pk != NULL, "P-256 keygen via the " PARITY_PROVIDER " provider");
    if (r != 1 || !pk) return 1;

    EVP_PKEY_CTX *dctx = EVP_PKEY_CTX_new(pk, NULL);
    CHECK(dctx != NULL, "legacy EVP_PKEY_CTX_new(pk, NULL)");
    unsigned char sec[64]; size_t secl = sizeof sec;
    int ri = EVP_PKEY_derive_init(dctx);
    int rs = EVP_PKEY_derive_set_peer(dctx, pk);
    int rd = (ri > 0 && rs > 0) ? EVP_PKEY_derive(dctx, sec, &secl) : -1;
    printf("legacy-ctor derive via " PARITY_PROVIDER "-served key: init=%d peer=%d derive=%d len=%zu\n",
           ri, rs, rd, rd == 1 ? secl : (size_t)0);
    CHECK(rd == 1 && secl == 32, "legacy-ctor ECDH succeeds (" PARITY_PROVIDER "-served)");

    EVP_KEYMGMT *km = EVP_KEYMGMT_fetch(NULL, "EC", NULL);
    OSSL_PROVIDER *kp = km ? EVP_KEYMGMT_get0_provider(km) : NULL;
    const char *kname = kp ? OSSL_PROVIDER_get0_name(kp) : "(core)";
    printf("NULL-propq EC keymgmt fetch resolves to: %s\n", kname);
    EVP_KEYMGMT_free(km);

    unsigned long e1 = 0, s1 = 0;
    gofipsOps(&e1, &s1);
    printf("gofips counters: ecdh %lu -> %lu, ecdsa %lu -> %lu\n", e0, e1, s0, s1);
    CHECK(e1 == e0 && s1 == s0,
          "gofips counters UNCHANGED (it claims none of the " PARITY_PROVIDER "-served work)");

    /* ECDSA through the same legacy shape */
    EVP_MD_CTX *m = EVP_MD_CTX_new();
    unsigned char msg[] = "fips-parity";
    size_t siglen = 0;
    int si = EVP_DigestSignInit(m, NULL, EVP_sha256(), NULL, pk);
    int sq = si > 0 ? EVP_DigestSign(m, NULL, &siglen, msg, sizeof msg - 1) : -1;
    unsigned char sig[96]; siglen = sizeof sig;
    int ss = sq > 0 ? EVP_DigestSign(m, sig, &siglen, msg, sizeof msg - 1) : -1;
    EVP_MD_CTX_free(m);
    printf("legacy-ctor DigestSign: init=%d query=%d sign=%d len=%zu\n",
           si, sq, ss, ss == 1 ? siglen : (size_t)0);
    CHECK(si > 0 && ss == 1, "legacy-ctor ECDSA sign succeeds (" PARITY_PROVIDER "-served)");
    unsigned long e2 = 0, s2 = 0;
    gofipsOps(&e2, &s2);
    CHECK(s2 == s1, "gofips ecdsa counter still UNCHANGED after the sign");

    EVP_PKEY_free(pk); EVP_PKEY_CTX_free(gctx); EVP_PKEY_CTX_free(dctx);
    printf("---\n%s\n", fails == 0 ? "ALL CHECKS PASSED" : "SOME CHECKS FAILED");
    return fails == 0 ? 0 : 1;
}
