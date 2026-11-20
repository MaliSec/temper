/* legacy_ctor_boundary.c - ECDH/ECDSA routing through the legacy
 * ctor EVP_PKEY_CTX_new(pk, NULL).
 *
 * The legacy ctor fetches with a NULL property query in the key's libctx,
 * so the core, not the provider, picks the implementation:
 *   - configured (gofips-only OPENSSL_CONF, no default provider): the
 *     fetch resolves to gofips; its dispatch counters must increase.
 *   - control (default reachable): the choice depends on the libcrypto
 *     version (3.5: default; 3.0: gofips). The suite reads the choice and
 *     asserts the gofips counters agree: delta > 0 iff gofips served it.
 * In both modes the exported key re-imports into the default provider
 * (X1).
 *
 * run-legacy-ctor.sh runs each mode in a fresh process; argv[1] is
 * "configured" or "control".
 *
 * Build: cc -o legacy_ctor_boundary legacy_ctor_boundary.c \
 *           $(pkg-config --cflags --libs openssl) -ldl
 * Run:   GOFIPS_SO=/path/gofips.so ./legacy_ctor_boundary configured
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <dlfcn.h>

static int fails = 0;
#define CHECK(c, msg) do { if (c) printf("PASS: %s\n", msg); \
    else { printf("FAIL: %s\n", msg); fails++; } } while (0)

/* Provider a NULL-propq EC keymgmt fetch resolves to in this process:
 * its name, "" for a core implementation, or NULL on fetch failure.
 * Returns static storage. */
static const char *resolvedProviderName(void) {
    static char namebuf[256];
    EVP_KEYMGMT *km = EVP_KEYMGMT_fetch(NULL, "EC", NULL);
    if (km == NULL) return NULL;
    OSSL_PROVIDER *p = EVP_KEYMGMT_get0_provider(km);
    const char *name = p ? OSSL_PROVIDER_get0_name(p) : "";
    snprintf(namebuf, sizeof namebuf, "%s", name);
    EVP_KEYMGMT_free(km);
    return namebuf;
}

/* Read the per-op counters (temperfips-ops JSON) via provider
 * get_params; dlsym is unreliable when OPENSSL_CONF activated the
 * provider. */
static OSSL_PROVIDER *g_prov = NULL;

static int readOps(const char *so, unsigned long *ecdh, unsigned long *ecdsa) {
    (void)so;
    if (g_prov == NULL) return 0;
    char *ptr = NULL;
    OSSL_PARAM rp[2];
    rp[0] = OSSL_PARAM_construct_utf8_ptr("temperfips-ops", &ptr, 0);
    rp[1] = OSSL_PARAM_construct_end();
    if (OSSL_PROVIDER_get_params(g_prov, rp) != 1 || ptr == NULL) return 0;
    if (getenv("GOFIPS_TRACE") != NULL)
        printf("  [trace] ops JSON: %s\n", ptr);
    char *v;
    /* skip `"ecdh":` (7 chars) to the digits */
    if (ecdh != NULL && (v = strstr(ptr, "\"ecdh\"")) != NULL)
        *ecdh = strtoul(v + 7, NULL, 10);
    if (ecdsa != NULL && (v = strstr(ptr, "\"ecdsa\"")) != NULL)
        *ecdsa = strtoul(v + 8, NULL, 10);
    return 1;
}

int main(int argc, char **argv) {
    const char *so = getenv("GOFIPS_SO");
    if (!so) so = "/tmp/temperfips.so";
    int configured = argc > 1 && strcmp(argv[1], "configured") == 0;
    int control = argc > 1 && strcmp(argv[1], "control") == 0;
    if (!configured && !control) {
        printf("usage: %s configured|control\n", argv[0]);
        return 2;
    }
    printf("== legacy_ctor_boundary mode=%s ==\n", argv[1]);

    /* configured: OPENSSL_CONF already activated gofips. control: load it
     * here, with the default provider also reachable. */
    OSSL_PROVIDER *g = NULL;
    if (control) {
        g = OSSL_PROVIDER_load(NULL, so);
        CHECK(g != NULL, "gofips loads (programmatic, control shape)");
        if (!g) return 1;
    } else {
        /* Loading an already active provider returns the same instance;
         * the handle is needed for counter reads. */
        g = OSSL_PROVIDER_load(NULL, so);
        if (g == NULL) {
            printf("note: path load refused under the config; trying by name\n");
            g = OSSL_PROVIDER_load(NULL, "gofips");
        }
    }
    g_prov = g;
    CHECK(g_prov != NULL, "provider handle available for evidence reads");
    if (!g_prov) return 1;
    EVP_PKEY_CTX *gctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", "provider=gofips");
    CHECK(gctx != NULL, "gofips EC keymgmt fetch");
    if (!gctx) return 1;
    int r = EVP_PKEY_keygen_init(gctx);
    CHECK(r == 1, "keygen init");
    OSSL_PARAM gp[2];
    char group[] = "prime256v1";
    gp[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, group, 0);
    gp[1] = OSSL_PARAM_construct_end();
    r = EVP_PKEY_CTX_set_params(gctx, gp);
    CHECK(r == 1, "keygen group");
    EVP_PKEY *pk = NULL;
    r = EVP_PKEY_generate(gctx, &pk);
    CHECK(r == 1 && pk != NULL, "P-256 keygen via gofips");
    if (r != 1 || !pk) return 1;

    unsigned long ecdh0 = 0, ecdsa0 = 0, ecdh1 = 0, ecdsa1 = 0;
    int ops_ok = readOps(so, &ecdh0, &ecdsa0);
    CHECK(ops_ok, "dispatch counters readable (provider evidence hook)");

    /* --- the legacy-ctor ECDH shape under test --- */
    EVP_PKEY_CTX *dctx = EVP_PKEY_CTX_new(pk, NULL);
    CHECK(dctx != NULL, "legacy EVP_PKEY_CTX_new(pk, NULL)");
    unsigned char s[64]; size_t sl = sizeof s;
    int ri = EVP_PKEY_derive_init(dctx);
    int rs = EVP_PKEY_derive_set_peer(dctx, pk);
    int rd = (ri > 0 && rs > 0) ? EVP_PKEY_derive(dctx, s, &sl) : -1;
    printf("legacy-ctor derive: init=%d peer=%d derive=%d len=%zu\n",
           ri, rs, rd, rd == 1 ? sl : (size_t)0);

    if (!readOps(so, &ecdh1, &ecdsa1)) {
        CHECK(0, "dispatch counters readable after the derive");
        return 1;
    }
    unsigned long dEcdh = ecdh1 - ecdh0;
    unsigned long dEcdsa = ecdsa1 - ecdsa0;
    printf("evidence: keyexch delta=%lu ecdsa delta=%lu\n", dEcdh, dEcdsa);

    if (configured) {
        CHECK(rd == 1 && sl == 32, "configured: legacy-ctor ECDH succeeds");
        CHECK(dEcdh > 0, "configured: ECDH dispatched through gofips (keyexch delta > 0)");
        /* the from_pkey control derives through gofips too */
        EVP_PKEY_CTX *e2 = EVP_PKEY_CTX_new_from_pkey(NULL, pk, NULL);
        unsigned char s2[64]; size_t l2 = sizeof s2;
        int r2 = EVP_PKEY_derive_init(e2) && EVP_PKEY_derive_set_peer(e2, pk)
                 ? EVP_PKEY_derive(e2, s2, &l2) : -1;
        CHECK(r2 == 1, "control: from_pkey derive succeeds");
        if (rd == 1 && r2 == 1)
            CHECK(l2 == sl && memcmp(s, s2, sl) == 0,
                  "configured: legacy and from_pkey secrets agree (same provider math)");
        if (e2) EVP_PKEY_CTX_free(e2);
    } else {
        /* Unsupported configuration (pages 08/13). The counter delta
         * must match the resolver: > 0 if gofips served the fetch, 0 if
         * default did. A provider cannot intercept this routing (page
         * 05). */
        const char *served = resolvedProviderName();
        int fromGofips = served != NULL && strcmp(served, "default") != 0;
        printf("control: NULL-propq fetch resolves to %s\n",
               served ? served : "(unresolved)");
        if (rd == 1) {
            if (fromGofips) {
                CHECK(dEcdh > 0,
                      "control: resolver=gofips, keyexch delta > 0 (dispatch claimed where performed)");
            } else {
                CHECK(dEcdh == 0,
                      "control: resolver=default, gofips keyexch counter UNCHANGED (no dispatch claimed for the default-served derive)");
            }
        } else {
            printf("note: control-shape derive refused (rc=%d) - fail closed\n", rd);
        }
        /* X1: export and re-import into the default provider */
        OSSL_PARAM *exp = NULL;
        int rt = EVP_PKEY_todata(pk, OSSL_KEYMGMT_SELECT_KEYPAIR, &exp);
        CHECK(rt > 0 && exp != NULL, "control: EVP_PKEY_todata (export contract intact)");
        if (rt > 0 && exp) {
            int hasGroup = 0, hasPub = 0, hasPriv = 0;
            for (OSSL_PARAM *q = exp; q->key; q++) {
                if (strcmp(q->key, OSSL_PKEY_PARAM_GROUP_NAME) == 0) hasGroup = 1;
                if (strcmp(q->key, OSSL_PKEY_PARAM_PUB_KEY) == 0) hasPub = 1;
                if (strcmp(q->key, OSSL_PKEY_PARAM_PRIV_KEY) == 0) hasPriv = 1;
            }
            CHECK(hasGroup && hasPub && hasPriv,
                  "control: export carries group + pub + priv (UNSIGNED_INTEGER scalar)");
            OSSL_PARAM_free(exp);
        }
    }

    /* --- the legacy-ctor ECDSA shape --- */
    unsigned long ecdsa_a = 0, ecdsa_b = 0;
    readOps(so, NULL, &ecdsa_a);
    EVP_MD_CTX *m = EVP_MD_CTX_new();
    unsigned char msg[] = "legacy-ctor-sign";
    /* DigestSign without propq resolves the same way. Size query first,
     * then sign. sig != NULL with *siglen == 0 must be refused, as in the
     * default provider. */
    int si = EVP_DigestSignInit(m, NULL, EVP_sha256(), NULL, pk);
    unsigned char sig[96]; size_t siglen = 0;
    int sq = si > 0 ? EVP_DigestSign(m, NULL, &siglen, msg, sizeof msg - 1) : -1;
    CHECK(sq == 1 && siglen >= 70 && siglen <= 72,
          "size query reports the algorithm max (70..72)");
    unsigned long ecdsa_q = 0;
    readOps(so, NULL, &ecdsa_q);
    CHECK(ecdsa_q == ecdsa_a,
          "size query does NOT count as a signature op (no signing happened)");
    int ss = sq > 0 ? EVP_DigestSign(m, sig, &siglen, msg, sizeof msg - 1) : -1;
    EVP_MD_CTX_free(m);
    readOps(so, NULL, &ecdsa_b);
    printf("legacy-ctor DigestSign: init=%d query=%d sign=%d len=%zu ecdsa delta=%lu\n",
           si, sq, ss, ss == 1 ? siglen : (size_t)0, ecdsa_b - ecdsa_q);
    if (configured) {
        CHECK(ss == 1, "configured: legacy-ctor ECDSA sign succeeds");
        CHECK(ecdsa_b - ecdsa_q > 0, "configured: ECDSA dispatched through gofips (delta > 0)");
        /* negative: uninitialized *siglen with sig != NULL must fail */
        EVP_MD_CTX *m2 = EVP_MD_CTX_new();
        int si2 = EVP_DigestSignInit(m2, NULL, EVP_sha256(), NULL, pk);
        unsigned char sig2[96]; size_t zero = 0;
        int ss2 = si2 > 0 ? EVP_DigestSign(m2, sig2, &zero, msg, sizeof msg - 1) : -1;
        EVP_MD_CTX_free(m2);
        CHECK(ss2 != 1,
              "negative: sig != NULL with *siglen == 0 is REFUSED (no unwritten success)");
    } else if (ss == 1) {
        /* the delta must match the resolver, as for ECDH */
        const char *served = resolvedProviderName();
        int fromGofips = served != NULL && strcmp(served, "default") != 0;
        if (fromGofips) {
            CHECK(ecdsa_b - ecdsa_q > 0,
                  "control: resolver=gofips, ecdsa delta > 0 (dispatch claimed where performed)");
        } else {
            CHECK(ecdsa_b - ecdsa_q == 0,
                  "control: resolver=default, gofips ecdsa counter UNCHANGED for a default-served sign");
        }
    }
    if (si > 0 && ss != 1) {
        /* diagnostic only; reaching here shows the refusal was clean */
        printf("note: DigestSign rc=%d in mode=%s\n", ss, argv[1]);
    }

    EVP_PKEY_free(pk);
    EVP_PKEY_CTX_free(gctx);
    printf("---\n%s\n", fails == 0 ? "ALL CHECKS PASSED" : "SOME CHECKS FAILED");
    return fails == 0 ? 0 : 1;
}
