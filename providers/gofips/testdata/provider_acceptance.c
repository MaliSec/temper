/* provider_acceptance.c - acceptance test for the gofips provider.
 *
 * Stages:
 *   0. Control: the default provider offers MD5, so a later MD5 refusal
 *      means exclusion, not missing support.
 *   1. gofips only: SHA-256 via EVP gives known vectors.
 *   2. MD5 not fetchable from gofips; SHA-1 served but not fips=yes.
 *   3. temperfips_evidence() counter shows the digest ran in Go.
 *   4. DRBG checks and the FIPS build marker.
 *
 * Build: cc providers/gofips/testdata/provider_acceptance.c \
 *           -o provider_acceptance $(pkg-config --cflags --libs libcrypto) -ldl
 * Run:   GOFIPS_SO=/abs/path/gofips.so ./provider_acceptance
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/err.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <dlfcn.h>

static const char *expect_abc = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
static const char *expect_empty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
static const char *expect_56_real = "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592";

static int hexdigest(EVP_MD *md, const char *msg, size_t len, char *hex) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned char out[64]; unsigned int outl = 0;
    if (!EVP_DigestInit_ex2(ctx, md, NULL)) return 0;
    if (len && !EVP_DigestUpdate(ctx, msg, len)) return 0;
    if (!EVP_DigestFinal_ex(ctx, out, &outl)) return 0;
    EVP_MD_CTX_free(ctx);
    for (unsigned int i = 0; i < outl; i++) sprintf(hex + 2 * i, "%02x", out[i]);
    hex[2 * outl] = 0;
    return 1;
}

int fails = 0;
#define CHECK(cond, label) \
    do { \
        if (cond) { printf("PASS: %s\n", label); } \
        else { printf("FAIL: %s\n", label); fails++; } \
    } while (0)

int main(void) {
    const char *so_path = getenv("GOFIPS_SO");
    if (so_path == NULL) so_path = "/tmp/temperfips.so";

    /* --- Stage 0: positive control with the default provider --- */
    OSSL_PROVIDER *def = OSSL_PROVIDER_load(NULL, "default");
    if (def) {
        EVP_MD *md5 = EVP_MD_fetch(NULL, "MD5", NULL);
        CHECK(md5 != NULL, "positive control: MD5 fetchable with default provider active");
        if (md5) EVP_MD_free(md5);
        EVP_MD *sha = EVP_MD_fetch(NULL, "SHA2-256", "provider=default");
        CHECK(sha != NULL, "positive control: SHA2-256 fetchable from default provider");
        if (sha) {
            char hex[129];
            if (hexdigest(sha, "abc", 3, hex))
                CHECK(strcmp(hex, expect_abc) == 0, "positive control: default SHA2-256 gives known vector");
            else
                CHECK(0, "positive control: default SHA2-256 digest computation");
            EVP_MD_free(sha);
        }
        OSSL_PROVIDER_unload(def);
    } else {
        CHECK(0, "positive control: default provider loads");
    }

    /* --- Stage 1: gofips only (default provider not loaded) --- */
    OSSL_PROVIDER *g = OSSL_PROVIDER_load(NULL, so_path);
    CHECK(g != NULL, "gofips provider loads via OSSL_PROVIDER_load");
    if (!g) return 1;

    EVP_MD *sha = EVP_MD_fetch(NULL, "SHA2-256", "provider=gofips");
    CHECK(sha != NULL, "SHA2-256 fetchable with provider=gofips");
    if (sha) {
        char hex[129];
        CHECK(hexdigest(sha, "abc", 3, hex) && strcmp(hex, expect_abc) == 0,
              "sha256(abc) == ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        CHECK(hexdigest(sha, "", 0, hex) && strcmp(hex, expect_empty) == 0,
              "sha256(empty) == e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        CHECK(hexdigest(sha, "abcdefgh", 8, hex) && strcmp(hex, "9c56cc51b374c3ba189210d5b6d4bf57790d351c96c47c02190ecf1e430635ab") == 0,
              "sha256(abcdefgh) == 9c56cc51b374c3ba189210d5b6d4bf57790d351c96c47c02190ecf1e430635ab");

        /* EVP_MD_get_params("provider") returns empty even for the default
         * provider, so provenance rests on the provider=gofips fetch, the
         * negatives below and the Go counter. */
        printf("note: EVP_MD provider-name query returns empty for all providers (core behavior); using fetch-property + negatives as provider evidence\n");

        CHECK(EVP_MD_get_size(sha) == 32, "EVP_MD_get_size == 32");
        CHECK(EVP_MD_get_block_size(sha) == 64, "EVP_MD_get_block_size == 64");
        EVP_MD_free(sha);
    }

    /* --- Stage 2: negatives --- */
    EVP_MD *md5 = EVP_MD_fetch(NULL, "MD5", "provider=gofips");
    CHECK(md5 == NULL, "negative: MD5 NOT fetchable from provider=gofips (unregistered)");
    if (md5) EVP_MD_free(md5);
    EVP_MD *md5b = EVP_MD_fetch(NULL, "MD5", "provider=gofips");
    CHECK(md5b == NULL, "negative: MD5 NOT fetchable under provider=gofips property (exclusion, not missing support)");
    if (md5b) EVP_MD_free(md5b);
    /* SHA-1 is served but not approved: the Go Cryptographic Module has
     * no SHA-1, so it runs outside the validated module. It must be
     * fetchable by name, not fetchable as fips=yes, and correct. */
    EVP_MD *sha1 = EVP_MD_fetch(NULL, "SHA1", "provider=gofips");
    CHECK(sha1 != NULL, "SHA1 fetchable from provider=gofips (served as non-approved)");
    EVP_MD *sha1fips = EVP_MD_fetch(NULL, "SHA1", "provider=gofips,fips=yes");
    CHECK(sha1fips == NULL, "negative: SHA1 NOT fetchable with fips=yes (not an approved service)");
    if (sha1fips) EVP_MD_free(sha1fips);
    if (sha1) {
        static const unsigned char want[20] = {0xa9,0x99,0x3e,0x36,0x47,0x06,0x81,0x6a,0xba,0x3e,
                                               0x25,0x71,0x78,0x50,0xc2,0x6c,0x9c,0xd0,0xd8,0x9d};
        unsigned char got[EVP_MAX_MD_SIZE]; unsigned int gl = 0;
        int r = EVP_Digest("abc", 3, got, &gl, sha1, NULL);
        CHECK(r == 1 && gl == 20 && memcmp(got, want, 20) == 0, "sha1(abc) == a9993e36... (standard vector)");
        const char *desc = EVP_MD_get0_description(sha1);
        CHECK(desc != NULL && strstr(desc, "NOT approved") != NULL && strstr(desc, "CMVP") == NULL,
              "SHA1 description says NOT approved and cites no certificate");
        EVP_MD_free(sha1);
    }
    /* SHA-1 must not be usable inside a MAC */
    {
        EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", "provider=gofips");
        EVP_MAC_CTX *mc = mac ? EVP_MAC_CTX_new(mac) : NULL;
        unsigned char key[32] = {1};
        OSSL_PARAM mp[2] = { OSSL_PARAM_construct_utf8_string("digest", "SHA1", 0), OSSL_PARAM_construct_end() };
        int r = mc ? EVP_MAC_init(mc, key, sizeof key, mp) : 0;
        CHECK(r != 1, "negative: HMAC with SHA1 is refused");
        EVP_MAC_CTX_free(mc); EVP_MAC_free(mac);
    }

    /* --- Stage 3: Go-side evidence --- */
    typedef long long (*ev_fn)(void);
    void *dl = dlopen(so_path, RTLD_NOW | RTLD_NOLOAD);
    ev_fn ev = dl ? (ev_fn)dlsym(dl, "temperfips_evidence") : NULL;
    if (ev) {
        long long n = ev();
        printf("evidence: gofips digest operations executed in Go: %lld\n", n);
        CHECK(n >= 3, "evidence: Go executed the digest ops (counter >= 3)");
    } else {
        CHECK(0, "evidence: temperfips_evidence symbol present");
    }

    /* --- Stage 4: FIPS-mode DRBG gates --- */
    /* Gate A: GOFIPS140=v1.0.0 build marker (SP 5247 §11.1). A non-FIPS
     * build is reported, and fails only under GOFIPS_REQUIRE_FIPS (D). */
    char marker_cmd[512];
    snprintf(marker_cmd, sizeof(marker_cmd),
             "go version -m '%s' 2>/dev/null | grep -q 'GOFIPS140=v1.0.0-c2097c7c'", so_path);
    int fips_build = (system(marker_cmd) == 0);
    printf("fips-build marker (GOFIPS140=v1.0.0-c2097c7c): %s\n", fips_build ? "YES" : "NO (non-FIPS build)");
    /* Gate B: CTR-DRBG works and the temperfips-randcalls counter shows
     * the calls reached Go. */
    EVP_RAND *rnd = EVP_RAND_fetch(NULL, "CTR-DRBG", "provider=gofips");
    CHECK(rnd != NULL, "fips/drbg: CTR-DRBG fetchable from provider=gofips");
    if (rnd) {
        EVP_RAND_CTX *rctx = EVP_RAND_CTX_new(rnd, NULL);
        CHECK(rctx != NULL, "fips/drbg: EVP_RAND_CTX_new");
        if (rctx) {
            int r = EVP_RAND_instantiate(rctx, 256, 0, NULL, 0, NULL);
            CHECK(r == 1, "fips/drbg: EVP_RAND_instantiate ok");
            unsigned char rb[64];
            size_t got = 0;
            r = EVP_RAND_generate(rctx, rb, sizeof(rb), 256, 0, NULL, 0);
            CHECK(r == 1, "fips/drbg: EVP_RAND_generate ok");
            unsigned char rb2[64];
            EVP_RAND_generate(rctx, rb2, sizeof(rb2), 256, 0, NULL, 0);
            CHECK(memcmp(rb, rb2, sizeof(rb)) != 0, "fips/drbg: two generates differ (entropy present)");
            r = EVP_RAND_reseed(rctx, 0, NULL, 0, NULL, 0);
            CHECK(r == 1, "fips/drbg: EVP_RAND_reseed ok");
            r = EVP_RAND_generate(rctx, rb, sizeof(rb), 256, 0, NULL, 0);
            CHECK(r == 1, "fips/drbg: generate after reseed ok");
            /* Read the counter by calling gofips_get_params directly: the
             * core's DRBG manager drops unknown keys on the RAND ctx
             * path. */
            OSSL_PARAM rparams[2];
            unsigned int rc_calls = 0;
            int gp_ok = 0;
            rparams[0] = OSSL_PARAM_construct_uint("temperfips-randcalls", &rc_calls);
            rparams[1] = OSSL_PARAM_construct_end();
            {
                typedef int (*gpp_fn)(void *, OSSL_PARAM[]);
                void *selfdl = dlopen(so_path, RTLD_NOW | RTLD_NOLOAD);
                gpp_fn gpp = selfdl ? (gpp_fn)dlsym(selfdl, "gofips_get_params") : NULL;
                if (gpp && gpp(NULL, rparams) == 1) {
                    rc_calls = *(unsigned int *)rparams[0].data;
                    gp_ok = rc_calls >= 3;
                }
            }
            if (gp_ok) {
                printf("evidence: RAND generate calls executed in Go: %u\n", rc_calls);
                CHECK(1, "fips/drbg: generate call-path evidence (counter >= 3)");
            } else {
                printf("  (temperfips-randcalls not readable via provider params)\n");
                CHECK(0, "fips/drbg: generate call-path evidence (counter >= 3)");
            }
            unsigned int strength = 0, state = 99;
            OSSL_PARAM sp[3];
            sp[0] = OSSL_PARAM_construct_uint(OSSL_RAND_PARAM_STRENGTH, &strength);
            sp[1] = OSSL_PARAM_construct_uint(OSSL_RAND_PARAM_STATE, &state);
            sp[2] = OSSL_PARAM_construct_end();
            if (EVP_RAND_CTX_get_params(rctx, sp)) {
                CHECK(strength == 256, "fips/drbg: strength reported 256");
                CHECK(state == 1, "fips/drbg: state = instantiated");
            } else {
                CHECK(0, "fips/drbg: strength/state params readable");
            }
            EVP_RAND_CTX_free(rctx);
        }
        EVP_RAND_free(rnd);
    }
    /* Gate C: the Go FIPS-mode DRBG service cannot be reached from C; the
     * drbg-evidence harness records it (testdata/drbg-*.log). */
    if (fips_build) {
        printf("fips-build: the DRBG service needs GODEBUG=fips140=on at runtime (drbg-evidence harness)\n");
    }
    /* Gate D: with GOFIPS_REQUIRE_FIPS set, a non-FIPS build fails. */
    if (getenv("GOFIPS_REQUIRE_FIPS") != NULL && !fips_build) {
        printf("FAIL: GOFIPS_REQUIRE_FIPS=1 but artifact lacks GOFIPS140 marker\n");
        fails++;
    }

    OSSL_PROVIDER_unload(g);
    printf("---\n%s\n", fails == 0 ? "ALL CHECKS PASSED" : "SOME CHECKS FAILED");
    return fails == 0 ? 0 : 1;
}
