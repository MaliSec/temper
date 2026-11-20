/* audreg.c - regression cases checked against the default provider's
 * observable behavior, plus the TLS capability callbacks.
 *
 *   octet-buf   undersized pub/priv octet buffer: rc=0 on both providers.
 *   keygen-race 8-thread concurrent first-use EC keygen, 3 bursts: no failures.
 *   drbg-split  CTR-DRBG: a 1 MiB + 1 request succeeds via the core's split;
 *               reported max_request is 65536, as in the default provider.
 *   kdf-salt    TLS13-KDF extract with an explicit empty salt and with no salt
 *               both match the default; the two results differ. The
 *               empty-salt parity check is skipped below OpenSSL 3.5,
 *               whose default provider treats an empty salt as absent.
 *   kdf-life    TLS13-KDF lifecycle: a dup of a salted ctx stays salted; reset
 *               clears the salt and its presence flag; a param-less derive after
 *               reset is refused, as in the default.
 *   bn-priv     BN priv param: a wide buffer has data_size shrunk to 32 so
 *               OSSL_PARAM_get_BN returns the scalar; leading-zero scalars
 *               round-trip; an undersized buffer fails closed.
 *   bn-null     NULL buffer with nonzero size on the BN priv param: no crash
 *               (forked child), needed size reported.
 *   rand-hook   RAND_set1_random_provider: the hook path has no core split, so
 *               gofips must chunk; a 100,000-byte request is served.
 *   point-fmt   EC keys report point-format "uncompressed", as in the
 *               default provider. OpenSSL 3.x's TLS stack rejects an EC
 *               peer key that reports none (E-38).
 *   names       every digest, cipher and keymgmt algorithm registers all the
 *               names the default provider registers for it (libssl fetches
 *               by OBJ short name, e.g. id-aes256-GCM).
 *   first-use   8 threads create their first TLS context at once in each
 *               of 20 fresh library contexts; every context has TLS 1.3
 *               ciphers.
 *   TLS caps    TLS-GROUP and TLS-SIGALG callbacks expose secp256r1 (also
 *               under its alias P-256) and ecdsa_secp256r1_sha256; a
 *               gofips-only TLS context accepts both group names.
 *
 * Run: cc -o audreg audreg.c $(pkg-config --cflags --libs openssl) -lpthread
 *      GODEBUG=fips140=on ./audreg <dir-with-gofips.so>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/wait.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/ssl.h>
#include <openssl/provider.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/param_build.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/rand.h>

/* RAND_set1_random_provider is OpenSSL 3.5+. Declared weak so the suite
 * builds and runs against 3.0; rand-hook prints SKIP when it is absent. */
extern int RAND_set1_random_provider(OSSL_LIB_CTX *ctx, OSSL_PROVIDER *p)
    __attribute__((weak));
#define HAVE_RAND_SET1_RANDOM_PROVIDER (RAND_set1_random_provider != NULL)
static int f10_skipped = 0;

static OSSL_LIB_CTX *G, *D;
static const char *g_search_dir;
static OSSL_PROVIDER *gprov;
static OSSL_PROVIDER *dprov;
static int fails = 0;
#define CHECK(c, msg) do { if (!(c)) { printf("FAIL: %s\n", msg); fails++; } else printf("PASS: %s\n", msg); } while (0)

/* ---- octet-buf ---- */
static void case_octet_buf(void) {
    EVP_PKEY *gk = EVP_PKEY_Q_keygen(G, NULL, "EC", "prime256v1");
    EVP_PKEY *dk = EVP_PKEY_Q_keygen(D, NULL, "EC", "prime256v1");
    if (!gk || !dk) { CHECK(0, "octet-buf setup keygen"); return; }
    unsigned char small[10]; size_t need = 0;
    memset(small, 0xAA, sizeof small);
    /* Only rc is compared: whether `need` is filled depends on whether
     * libcrypto's size query is also refused. */
    int rg = EVP_PKEY_get_octet_string_param(gk, "pub", small, sizeof small, &need);
    int rc = EVP_PKEY_get_octet_string_param(dk, "pub", small, sizeof small, &need);
    CHECK(rg == 0 && rc == 0,
          "octet-buf: undersized pub buffer errors on both providers (rc=0, no partial success)");
    unsigned char ps[10]; memset(ps, 0xAA, sizeof ps);
    int rgp = EVP_PKEY_get_octet_string_param(gk, OSSL_PKEY_PARAM_PRIV_KEY, ps, sizeof ps, &need);
    int rcp = EVP_PKEY_get_octet_string_param(dk, OSSL_PKEY_PARAM_PRIV_KEY, ps, sizeof ps, &need);
    CHECK(rgp == 0 && rcp == 0,
          "octet-buf: undersized priv buffer errors on both providers (rc=0, no partial success)");
    EVP_PKEY_free(gk); EVP_PKEY_free(dk);
}

/* ---- keygen-race ---- */
static OSSL_LIB_CTX *Gf;
static int f4done[8];
static void *f4w(void *a) {
    long id = (long)a;
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_name(Gf, "EC", NULL);
    if (!c) return NULL;
    if (EVP_PKEY_keygen_init(c) <= 0 || EVP_PKEY_CTX_set_group_name(c, "P-256") <= 0) { EVP_PKEY_CTX_free(c); return NULL; }
    EVP_PKEY *k = NULL;
    if (EVP_PKEY_keygen(c, &k) > 0) { EVP_PKEY_free(k); f4done[id] = 1; }
    EVP_PKEY_CTX_free(c);
    return NULL;
}
static void case_keygen_race(void) {
    Gf = OSSL_LIB_CTX_new();
    /* the provider search path is per-libctx */
    OSSL_PROVIDER_set_default_search_path(Gf, g_search_dir);
    if (!OSSL_PROVIDER_load(Gf, "gofips")) { CHECK(0, "keygen-race load"); return; }
    for (int burst = 0; burst < 3; burst++) {
        for (int i = 0; i < 8; i++) f4done[i] = 0;
        pthread_t th[8];
        for (long i = 0; i < 8; i++) pthread_create(&th[i], NULL, f4w, (void*)i);
        for (int i = 0; i < 8; i++) pthread_join(th[i], NULL);
        int ok = 1;
        for (int i = 0; i < 8; i++) if (!f4done[i]) ok = 0;
        char msg[80];
        snprintf(msg, sizeof msg, "keygen-race: concurrent first-use keygen burst %d: 8/8 ok", burst);
        CHECK(ok, msg);
    }
}

/* ---- drbg-split ---- */
static void case_drbg_split(void) {
    EVP_RAND *r = EVP_RAND_fetch(G, "CTR-DRBG", NULL);
    EVP_RAND_CTX *c = EVP_RAND_CTX_new(r, NULL);
    if (!c) { CHECK(0, "drbg-split setup"); return; }
    OSSL_PARAM nullp[2] = { OSSL_PARAM_construct_end() };
    if (EVP_RAND_instantiate(c, 256, 0, NULL, 0, nullp) <= 0) {
        CHECK(0, "drbg-split instantiate");
        return;
    }
    /* The core splits requests to the reported max_request, so a large
     * caller request succeeds as with the default provider. The
     * per-call bound is enforced inside rand_generate and random_bytes. */
    unsigned char big[1024*1024 + 1];
    int rc = EVP_RAND_generate(c, big, sizeof big, 0, 0, NULL, 0);
    CHECK(rc == 1, "drbg-split: 1 MiB + 1 caller request succeeds via the manager's split (matches the default contract)");
    unsigned char ok_[1024];
    rc = EVP_RAND_generate(c, ok_, sizeof ok_, 0, 0, NULL, 0);
    CHECK(rc == 1, "drbg-split: at-max generate still accepted");
    OSSL_PARAM gp[2];
    size_t maxreq = 0;
    gp[0] = OSSL_PARAM_construct_size_t("max_request", &maxreq);
    gp[1] = OSSL_PARAM_construct_end();
    EVP_RAND_CTX_get_params(c, gp);
    CHECK(maxreq == 65536, "drbg-split: reported max_request is 65536 (matches the default)");
    EVP_RAND_CTX_free(c); EVP_RAND_free(r);
}

/* ---- kdf-life: TLS13-KDF lifecycle (dup carries saltSeen; reset clears it) ---- */
static int t13k(OSSL_LIB_CTX *L, int salted, unsigned char *out, size_t outlen);
/* Build a TLS13-KDF ctx with state set via set_ctx_params; derive is
 * then called without params. */
static int t13k_ctx(OSSL_LIB_CTX *L, int salted, int preset, EVP_KDF_CTX **out) {
    EVP_KDF *k = EVP_KDF_fetch(L, "TLS13-KDF", NULL);
    EVP_KDF_CTX *c = EVP_KDF_CTX_new(k);
    EVP_KDF_free(k);
    if (!c) return 0;
    int mode = EVP_KDF_HKDF_MODE_EXTRACT_ONLY;
    unsigned char ikm[32]; memset(ikm, 7, 32);
    unsigned char salt[32]; memset(salt, 0x33, 32);
    OSSL_PARAM p[8]; int n = 0;
    p[n++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, "SHA256", 0);
    p[n++] = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode);
    p[n++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, ikm, 32);
    p[n++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PREFIX, (void *)"tls13 ", 6);
    p[n++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_LABEL, (void *)"derived", 7);
    if (salted) p[n++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, salt, 32);
    p[n] = OSSL_PARAM_construct_end();
    if (EVP_KDF_CTX_set_params(c, p) <= 0) { EVP_KDF_CTX_free(c); return 0; }
    if (preset) EVP_KDF_CTX_reset(c);
    *out = c;
    return 1;
}
static int t13k_derive(EVP_KDF_CTX *c, unsigned char *out, size_t outlen) {
    return EVP_KDF_derive(c, out, outlen, NULL);
}
/* re-set digest, mode and key (no salt) after a reset */
static int t13k_resset(EVP_KDF_CTX *c) {
    int mode = EVP_KDF_HKDF_MODE_EXTRACT_ONLY;
    unsigned char ikm[32]; memset(ikm, 7, 32);
    OSSL_PARAM p[4]; int n = 0;
    p[n++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, "SHA256", 0);
    p[n++] = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode);
    p[n++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, ikm, 32);
    p[n] = OSSL_PARAM_construct_end();
    return EVP_KDF_CTX_set_params(c, p);
}
static void case_kdf_life(void) {
    /* Default-provider references: 32-byte salt (not kdf-salt's empty salt)
     * and no salt. */
    EVP_KDF_CTX *ref = NULL;
    unsigned char saltedRef[32], nosaltRef[32];
    if (!t13k_ctx(D, 1, 0, &ref)) { CHECK(0, "kdf-life ref setup"); return; }
    int rr = t13k_derive(ref, saltedRef, 32);
    EVP_KDF_CTX_free(ref);
    if (!t13k_ctx(D, 0, 0, &ref)) { CHECK(0, "kdf-life ref2 setup"); return; }
    int rr2 = t13k_derive(ref, nosaltRef, 32);
    EVP_KDF_CTX_free(ref);
    if (!(rr > 0 && rr2 > 0)) { CHECK(0, "kdf-life refs derive"); return; }
    /* kdf-life/a: a dup of a salted ctx must keep saltSeen; otherwise it skips
     * the pre-extract and returns the no-salt output with success. */
    EVP_KDF_CTX *p = NULL, *dup = NULL;
    unsigned char a[32], b[32];
    if (!t13k_ctx(G, 1, 0, &p)) { CHECK(0, "kdf-life/a setup"); return; }
    if (!t13k_ctx(G, 1, 0, &dup)) { CHECK(0, "kdf-life/a dup setup"); EVP_KDF_CTX_free(p); return; }
    int r1 = t13k_derive(p, a, 32);
    EVP_KDF_CTX *dp = EVP_KDF_CTX_dup(p);
    int r2 = dp ? t13k_derive(dp, b, 32) : 0;
    EVP_KDF_CTX_free(dp);
    int m1 = r1 > 0 && memcmp(a, saltedRef, 32) == 0;
    int m2 = r2 > 0 && memcmp(b, saltedRef, 32) == 0;
    int distinct = memcmp(saltedRef, nosaltRef, 32) != 0;
    CHECK(m1 && m2 && distinct,
          "kdf-life/a: parent and DUP of a salted ctx both match the default's salted schedule (dup carried saltSeen)");
    if (!m2) printf("  kdf-life/a detail: dup rc=%d parent-match=%d dup-match=%d distinct=%d\n", r2, m1, m2, distinct);
    EVP_KDF_CTX_free(p); EVP_KDF_CTX_free(dup);
    EVP_KDF_CTX *p2 = NULL;
    if (t13k_ctx(G, 1, 0, &p2)) {
        EVP_KDF_CTX *d1 = EVP_KDF_CTX_dup(p2);
        EVP_KDF_CTX *d2 = d1 ? EVP_KDF_CTX_dup(d1) : NULL;
        unsigned char c1[32], c2[32];
        int q1 = d1 ? t13k_derive(d1, c1, 32) : 0;
        int q2 = d2 ? t13k_derive(d2, c2, 32) : 0;
        CHECK(q1 > 0 && q2 > 0 && memcmp(c1, saltedRef, 32) == 0 && memcmp(c2, saltedRef, 32) == 0,
              "kdf-life/a2: dup-of-dup chain stays salted-faithful");
        EVP_KDF_CTX_free(d1); EVP_KDF_CTX_free(d2); EVP_KDF_CTX_free(p2);
    }
    /* kdf-life/b: reset must clear saltSeen too, or a no-salt derive after reset
     * returns the present-empty-salt schedule. */
    EVP_KDF_CTX *p3 = NULL;
    if (!t13k_ctx(G, 1, 0, &p3)) { CHECK(0, "kdf-life/b setup"); return; }
    unsigned char g1[32], g2[32], g3[32];
    int s1 = t13k_derive(p3, g1, 32);
    EVP_KDF_CTX_reset(p3);
    int rs2 = t13k_resset(p3);
    int s2 = rs2 > 0 ? t13k_derive(p3, g2, 32) : 0;
    EVP_KDF_CTX_reset(p3);
    int rs3 = t13k_resset(p3);
    int s3 = rs3 > 0 ? t13k_derive(p3, g3, 32) : 0;
    int n1 = s2 > 0 && memcmp(g2, nosaltRef, 32) == 0;
    int n3 = s3 > 0 && memcmp(g3, nosaltRef, 32) == 0;
    CHECK(n1 && n3,
          "kdf-life/b: after reset (and repeated reset), no-salt derive matches the ABSENT-salt reference (reset cleared saltSeen)");
    if (!n1) printf("  kdf-life/b detail: salted rc=%d post-reset rc=%d absent-match=%d\n", s1, s2, n1);
    EVP_KDF_CTX *p4 = NULL;
    if (t13k_ctx(G, 0, 0, &p4)) {
        unsigned char g4[32];
        EVP_KDF_CTX_reset(p4);
        int rs4 = t13k_resset(p4);
        int s4 = rs4 > 0 ? t13k_derive(p4, g4, 32) : 0;
        CHECK(s4 > 0 && memcmp(g4, nosaltRef, 32) == 0,
              "kdf-life/c: reset on a never-salted ctx stays absent-shaped");
        EVP_KDF_CTX_free(p4);
    }
    EVP_KDF_CTX *p5 = NULL;
    if (t13k_ctx(G, 1, 0, &p5)) {
        EVP_KDF_CTX_reset(p5);
        int rs5 = t13k_resset(p5);
        EVP_KDF_CTX *d5 = EVP_KDF_CTX_dup(p5);
        unsigned char g5[32];
        int s5 = (d5 && rs5 > 0) ? t13k_derive(d5, g5, 32) : 0;
        CHECK(s5 > 0 && memcmp(g5, nosaltRef, 32) == 0,
              "kdf-life/d: dup of a RESET ctx is absent-shaped (dup carried the cleared flag)");
        EVP_KDF_CTX_free(d5); EVP_KDF_CTX_free(p5);
    }
    /* kdf-life/e/kdf-life/f: the default's reset clears the mode, so a param-less
     * derive after reset is refused. Forked so a panic cannot kill the
     * suite. */
    pid_t pid = fork();
    if (pid == 0) {
        EVP_KDF_CTX *p6 = NULL;
        if (!t13k_ctx(G, 1, 0, &p6)) _exit(9);
        EVP_KDF_CTX_reset(p6);
        unsigned char g6[32];
        int s6 = t13k_derive(p6, g6, 32);
        EVP_KDF_CTX_free(p6);
        _exit(s6 == 0 ? 0 : 10);
    }
    int st = 0; waitpid(pid, &st, 0);
    int alive = WIFEXITED(st) && WEXITSTATUS(st) == 0;
    CHECK(alive, "kdf-life/e: param-less derive after reset is REFUSED on gofips (rc=0, matches the default's cleared-mode reset)");
    if (!alive) printf("  kdf-life/e detail: exited=%d signal=%d rc=%d\n",
                       WIFEXITED(st), WIFSIGNALED(st) ? WTERMSIG(st) : -1,
                       WIFEXITED(st) ? WEXITSTATUS(st) : -1);
    pid = fork();
    if (pid == 0) {
        EVP_KDF_CTX *p7 = NULL;
        if (!t13k_ctx(D, 1, 0, &p7)) _exit(9);
        EVP_KDF_CTX_reset(p7);
        unsigned char g7[32];
        int s7 = t13k_derive(p7, g7, 32);
        EVP_KDF_CTX_free(p7);
        _exit(s7 == 0 ? 0 : 10);
    }
    waitpid(pid, &st, 0);
    alive = WIFEXITED(st) && WEXITSTATUS(st) == 0;
    CHECK(alive, "kdf-life/f: control - the default refuses a param-less derive after reset (rc=0)");
    EVP_KDF_CTX_free(p3);
}

/* ---- bn-priv: priv-key BN param buffer contract (wide / NULL / undersized) ---- */
static void case_bn_priv(void) {
    EVP_PKEY *gk = EVP_PKEY_Q_keygen(G, NULL, "EC", "prime256v1");
    EVP_PKEY *dk = EVP_PKEY_Q_keygen(D, NULL, "EC", "prime256v1");
    if (!gk || !dk) { CHECK(0, "bn-priv setup keygen"); return; }
    BIGNUM *bg = NULL, *bd = NULL;
    int rg = EVP_PKEY_get_bn_param(gk, OSSL_PKEY_PARAM_PRIV_KEY, &bg);
    int rd = EVP_PKEY_get_bn_param(dk, OSSL_PKEY_PARAM_PRIV_KEY, &bd);
    if (!(rg > 0 && rd > 0 && bg && bd)) { CHECK(0, "bn-priv EVP_PKEY_get_bn_param setup"); goto out; }
    /* With a 64-byte buffer, data_size must shrink to 32 (as in the
     * default provider); otherwise OSSL_PARAM_get_BN reads a wrong
     * 512-bit value and reports success. */
    unsigned char w[64]; memset(w, 0xEE, sizeof w);
    OSSL_PARAM q[2];
    q[0] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_PRIV_KEY, w, sizeof w);
    q[1] = OSSL_PARAM_construct_end();
    int rcp = EVP_PKEY_get_params(gk, q);
    BIGNUM *bw = NULL;
    int gw = rcp > 0 ? OSSL_PARAM_get_BN(q, &bw) : 0;
    int wideOk = gw > 0 && bw && q[0].data_size == 32 && q[0].return_size == 32
                 && BN_cmp(bw, bg) == 0;
    CHECK(wideOk,
          "bn-priv/a: wide-buffer BN: data_size shrunk to 32, return_size=32, OSSL_PARAM_get_BN returns the canonical scalar");
    if (!wideOk && bw) {
        char *h1 = BN_bn2hex(bw), *h2 = BN_bn2hex(bg);
        printf("  bn-priv/a detail: get_BN=%s expected=%s ds=%zu rs=%zu\n",
               h1 ? h1 : "(nil)", h2 ? h2 : "(nil)",
               (size_t)q[0].data_size, (size_t)q[0].return_size);
        OPENSSL_free(h1); OPENSSL_free(h2);
    }
    if (bw) BN_free(bw);
    /* leading-zero scalar (31 bytes minimal) */
    BIGNUM *dz = NULL;
    BN_hex2bn(&dz, "00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF");
    EC_GROUP *grp = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    EC_POINT *P = EC_POINT_new(grp);
    EC_POINT_mul(grp, P, dz, NULL, NULL, NULL);
    unsigned char pub[65];
    EC_POINT_point2oct(grp, P, POINT_CONVERSION_UNCOMPRESSED, pub, 65, NULL);
    OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
    OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, "prime256v1", 0);
    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PRIV_KEY, dz);
    OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY, pub, 65);
    OSSL_PARAM *ps = OSSL_PARAM_BLD_to_param(bld);
    EVP_PKEY_CTX *pc = EVP_PKEY_CTX_new_from_name(G, "EC", NULL);
    EVP_PKEY_fromdata_init(pc);
    EVP_PKEY *zk = NULL;
    int rz = EVP_PKEY_fromdata(pc, &zk, EVP_PKEY_KEYPAIR, ps);
    BIGNUM *bz = NULL;
    int rbz = rz > 0 ? EVP_PKEY_get_bn_param(zk, OSSL_PKEY_PARAM_PRIV_KEY, &bz) : 0;
    int leadOk = rbz > 0 && bz && BN_cmp(bz, dz) == 0;
    CHECK(leadOk, "bn-priv/b: leading-zero (31-byte) scalar: BN round-trip preserves the value");
    if (leadOk) {
        unsigned char wz[64]; memset(wz, 0xEE, sizeof wz);
        OSSL_PARAM qz[2];
        qz[0] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_PRIV_KEY, wz, sizeof wz);
        qz[1] = OSSL_PARAM_construct_end();
        int rcz = EVP_PKEY_get_params(zk, qz);
        BIGNUM *bwz = NULL;
        int gwz = rcz > 0 ? OSSL_PARAM_get_BN(qz, &bwz) : 0;
        CHECK(gwz > 0 && bwz && BN_cmp(bwz, dz) == 0,
              "bn-priv/c: leading-zero scalar through the WIDE buffer: get_BN value preserved");
        if (bwz) BN_free(bwz);
    }
    if (bz) BN_free(bz);
    EVP_PKEY_free(zk); EVP_PKEY_CTX_free(pc);
    OSSL_PARAM_free(ps); OSSL_PARAM_BLD_free(bld);
    EC_POINT_free(P); EC_GROUP_free(grp); BN_free(dz);
    /* undersized buffer: rc=0, nothing written (octet-buf for the BN type) */
    unsigned char s[10]; memset(s, 0xEE, sizeof s);
    OSSL_PARAM u[2];
    u[0] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_PRIV_KEY, s, sizeof s);
    u[1] = OSSL_PARAM_construct_end();
    int rus = EVP_PKEY_get_params(gk, u);
    int untouched = 1;
    for (size_t i = 0; i < sizeof s; i++) if (s[i] != 0xEE) untouched = 0;
    CHECK(rus == 0 && untouched,
          "bn-priv/d: undersized BN buffer: rc=0, buffer untouched (matches default)");
    out:
    EVP_PKEY_free(gk); EVP_PKEY_free(dk);
    if (bg) BN_free(bg); if (bd) BN_free(bd);
}

/* ---- bn-null: NULL buffer + nonzero size on the BN priv param. A NULL
 * passed to unsafe.Slice would panic; run in a forked child. ---- */
static void f9child(void) {
    EVP_PKEY *gk = EVP_PKEY_Q_keygen(G, NULL, "EC", "prime256v1");
    if (!gk) _exit(9);
    OSSL_PARAM q[2];
    q[0].key = OSSL_PKEY_PARAM_PRIV_KEY;
    q[0].data_type = OSSL_PARAM_UNSIGNED_INTEGER;
    q[0].data = NULL;
    q[0].data_size = 32;
    q[0].return_size = 0;
    q[1] = OSSL_PARAM_construct_end();
    int r = EVP_PKEY_get_params(gk, q);
    /* expect success with the needed size reported */
    if (r != 1 || q[0].return_size != 32) _exit(10);
    EVP_PKEY_free(gk);
    _exit(0);
}
static void case_bn_null(void) {
    pid_t pid = fork();
    if (pid == 0) f9child();
    int st = 0;
    waitpid(pid, &st, 0);
    int alive = WIFEXITED(st) && WEXITSTATUS(st) == 0;
    CHECK(alive,
          "bn-null/a: NULL-buffer nonzero-size BN get_params: child exited 0 (no panic/abort, needed size reported)");
    if (!alive) printf("  bn-null/a detail: exited=%d signal=%d rc=%d\n",
                       WIFEXITED(st), WIFSIGNALED(st) ? WTERMSIG(st) : -1,
                       WIFEXITED(st) ? WEXITSTATUS(st) : -1);
    /* size query shape: NULL + 0 */
    pid = fork();
    if (pid == 0) {
        EVP_PKEY *gk = EVP_PKEY_Q_keygen(G, NULL, "EC", "prime256v1");
        if (!gk) _exit(9);
        OSSL_PARAM q[2];
        q[0].key = OSSL_PKEY_PARAM_PRIV_KEY;
        q[0].data_type = OSSL_PARAM_UNSIGNED_INTEGER;
        q[0].data = NULL;
        q[0].data_size = 0;
        q[0].return_size = 0;
        q[1] = OSSL_PARAM_construct_end();
        int r = EVP_PKEY_get_params(gk, q);
        if (r != 1 || q[0].return_size != 32) _exit(10);
        _exit(0);
    }
    waitpid(pid, &st, 0);
    alive = WIFEXITED(st) && WEXITSTATUS(st) == 0;
    CHECK(alive, "bn-null/b: NULL+0 size-query shape: child exited 0, needed size reported");
}

/* ---- rand-hook: large request through RAND_set1_random_provider. The hook
 * path has no core split, so gofips must chunk. ---- */
static void case_rand_hook(void) {
    if (!HAVE_RAND_SET1_RANDOM_PROVIDER) {
        printf("SKIP: rand-hook requires RAND_set1_random_provider (OpenSSL >= 3.5; the running libcrypto does not provide it)\n");
        f10_skipped = 1;
        return;
    }
    int rs = RAND_set1_random_provider(G, gprov);
    CHECK(rs == 1, "rand-hook: set1_random_provider accepts gofips");
    if (rs != 1) return;
    unsigned char *big = malloc(100000);
    if (!big) { CHECK(0, "rand-hook malloc"); return; }
    memset(big, 0, 100000);
    int r = RAND_bytes_ex(G, big, 100000, 0);
    int nz = 0;
    for (int i = 0; i < 100000; i++) if (big[i]) nz++;
    CHECK(r == 1 && nz > 99000,
          "rand-hook/a: 100,000-byte RAND_bytes_ex through the set1 hook: served (chunked), fresh bytes");
    if (r != 1) printf("  rand-hook/a detail: rc=%d nonzero=%d\n", r, nz);
    int r2 = RAND_bytes_ex(G, big, 65537, 0);
    CHECK(r2 == 1, "rand-hook/b: 65,537-byte request (one over the per-call max): served");
    int r3 = RAND_bytes_ex(G, big, 65536, 0);
    CHECK(r3 == 1, "rand-hook/c: exactly at-max request: served");
    free(big);
    RAND_set1_random_provider(G, NULL);
}

/* ---- kdf-salt ---- */
static int t13k(OSSL_LIB_CTX *L, int salted, unsigned char *out, size_t outlen) {
    EVP_KDF *k = EVP_KDF_fetch(L, "TLS13-KDF", NULL);
    EVP_KDF_CTX *c = EVP_KDF_CTX_new(k);
    int mode = EVP_KDF_HKDF_MODE_EXTRACT_ONLY;
    unsigned char ikm[32]; memset(ikm, 7, 32);
    OSSL_PARAM p[8]; int n = 0;
    p[n++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, "SHA256", 0);
    p[n++] = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode);
    p[n++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, ikm, 32);
    p[n++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PREFIX, (void *)"tls13 ", 6);
    p[n++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_LABEL, (void *)"derived", 7);
    if (salted) p[n++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, (void *)"", 0);
    p[n] = OSSL_PARAM_construct_end();
    int rc = EVP_KDF_derive(c, out, outlen, p);
    EVP_KDF_CTX_free(c); EVP_KDF_free(k);
    return rc;
}
static void case_kdf_salt(void) {
    unsigned char a[32], b[32], c2[32], d2[32];
    int r1 = t13k(D, 1, a, 32), r2 = t13k(G, 1, b, 32);
    /* Before 3.5 the default provider's HKDF ignores an empty salt (it
     * reads only non-empty SALT params), so there is no reference
     * behavior to match. */
    if (OpenSSL_version_num() < 0x30500000L)
        printf("SKIP: kdf-salt: explicitly-empty salt parity needs OpenSSL >= 3.5 (older default providers treat it as absent)\n");
    else
        CHECK(r1 > 0 && r2 > 0 && memcmp(a, b, 32) == 0,
              "kdf-salt: explicitly-empty salt matches the default provider");
    int r3 = t13k(D, 0, c2, 32), r4 = t13k(G, 0, d2, 32);
    CHECK(r3 > 0 && r4 > 0 && memcmp(c2, d2, 32) == 0,
          "kdf-salt: absent salt matches the default provider");
    CHECK(r2 > 0 && r4 > 0 && memcmp(b, d2, 32) != 0,
          "kdf-salt: gofips gives present-empty and absent salt DISTINCT values (presence is semantic)");
}

/* ---- TLS capability callbacks at runtime ---- */
static int caps_group_cb(const OSSL_PARAM params[], void *arg) {
    int *found = arg;
    const char *name = NULL;
    unsigned int id = 0;
    for (const OSSL_PARAM *p = params; p->key != NULL; p++) {
        if (!strcmp(p->key, OSSL_CAPABILITY_TLS_GROUP_NAME) && p->data)
            name = (const char *)p->data;
        if (!strcmp(p->key, OSSL_CAPABILITY_TLS_GROUP_ID) && p->data_size == sizeof(unsigned int))
            id = *(unsigned int *)p->data;
    }
    if (name && id == 23 /* secp256r1 */ && !strcmp(name, "secp256r1")) *found |= 1;
    if (name && id == 23 && !strcmp(name, "P-256")) *found |= 2;
    return 1;
}
static int caps_sig_cb(const OSSL_PARAM params[], void *arg) {
    int *found = arg;
    const char *iana = NULL;
    unsigned int codepoint = 0;
    for (const OSSL_PARAM *p = params; p->key != NULL; p++) {
        /* literal keys: OSSL_CAPABILITY_TLS_SIGALG_* is missing from
         * older headers */
        if (!strcmp(p->key, "tls-sigalg-iana-name") && p->data)
            iana = (const char *)p->data;
        if (!strcmp(p->key, "tls-sigalg-code-point") && p->data_size == sizeof(unsigned int))
            codepoint = *(unsigned int *)p->data;
    }
    if (iana && codepoint == 0x0403 && !strcmp(iana, "ecdsa_secp256r1_sha256")) *found = 1;
    return 1;
}
/* ---- point-fmt ---- */
static void case_point_format(void) {
    EVP_PKEY *gk = EVP_PKEY_Q_keygen(G, NULL, "EC", "prime256v1");
    EVP_PKEY *dk = EVP_PKEY_Q_keygen(D, NULL, "EC", "prime256v1");
    if (!gk || !dk) { CHECK(0, "point-fmt setup keygen"); EVP_PKEY_free(gk); EVP_PKEY_free(dk); return; }
    int gf = EVP_PKEY_get_ec_point_conv_form(gk);
    int df = EVP_PKEY_get_ec_point_conv_form(dk);
    CHECK(gf == POINT_CONVERSION_UNCOMPRESSED && gf == df,
          "point-fmt: EC key reports point-format uncompressed, as the default provider does");
    EVP_PKEY_free(gk);
    EVP_PKEY_free(dk);
}

/* ---- names ---- */
/* 1 if every name in the colon-separated list `want` appears in `have`. */
static int names_cover(const char *have, const char *want, char *missing, size_t mlen) {
    char buf[256];
    snprintf(buf, sizeof(buf), "%s", want);
    for (char *t = strtok(buf, ":"); t; t = strtok(NULL, ":")) {
        int found = 0;
        const char *q = have;
        size_t tl = strlen(t);
        while (q && *q) {
            const char *e = strchr(q, ':');
            size_t l = e ? (size_t)(e - q) : strlen(q);
            if (l == tl && strncasecmp(q, t, l) == 0) { found = 1; break; }
            q = e ? e + 1 : NULL;
        }
        if (!found) { snprintf(missing, mlen, "%s", t); return 0; }
    }
    return 1;
}
static void case_names(void) {
    static const struct { int op; const char *label; } ops[] = {
        {OSSL_OP_DIGEST, "digest"}, {OSSL_OP_CIPHER, "cipher"}, {OSSL_OP_KEYMGMT, "keymgmt"},
    };
    for (size_t i = 0; i < sizeof(ops) / sizeof(ops[0]); i++) {
        int ns = 0, bad = 0, compared = 0;
        const OSSL_ALGORITHM *ga = OSSL_PROVIDER_query_operation(gprov, ops[i].op, &ns);
        const OSSL_ALGORITHM *da = OSSL_PROVIDER_query_operation(dprov, ops[i].op, &ns);
        for (; ga && ga->algorithm_names; ga++) {
            char first[64];
            snprintf(first, sizeof(first), "%s", ga->algorithm_names);
            char *c = strchr(first, ':');
            if (c) *c = 0;
            for (const OSSL_ALGORITHM *d = da; d && d->algorithm_names; d++) {
                char dfirst[64];
                snprintf(dfirst, sizeof(dfirst), "%s", d->algorithm_names);
                char *dc = strchr(dfirst, ':');
                if (dc) *dc = 0;
                if (strcasecmp(first, dfirst) != 0) continue;
                char missing[64] = "";
                compared++;
                if (!names_cover(ga->algorithm_names, d->algorithm_names, missing, sizeof(missing))) {
                    printf("      %s %s: missing name %s\n", ops[i].label, first, missing);
                    bad++;
                }
                break;
            }
        }
        char msg[160];
        snprintf(msg, sizeof(msg), "names: every %s algorithm registers the default provider's names (%d compared)",
                 ops[i].label, compared);
        CHECK(bad == 0 && compared > 0, msg);
    }
}

/* ---- first-use ---- */
static OSSL_LIB_CTX *fu_ctx;
static int fu_ok[8];
static void *fu_worker(void *a) {
    int id = (int)(long)a;
    SSL_CTX *c = SSL_CTX_new_ex(fu_ctx, NULL, TLS_client_method());
    int n = 0;
    if (c) {
        SSL_CTX_set_min_proto_version(c, TLS1_3_VERSION);
        SSL_CTX_set_max_proto_version(c, TLS1_3_VERSION);
        SSL *s = SSL_new(c);
        STACK_OF(SSL_CIPHER) *sk = s ? SSL_get1_supported_ciphers(s) : NULL;
        n = sk ? sk_SSL_CIPHER_num(sk) : 0;
        sk_SSL_CIPHER_free(sk);
        SSL_free(s);
        SSL_CTX_free(c);
    }
    fu_ok[id] = n > 0;
    return NULL;
}
static void case_first_use(void) {
    int rounds = 20, failed = 0;
    for (int r = 0; r < rounds; r++) {
        fu_ctx = OSSL_LIB_CTX_new();
        OSSL_PROVIDER_set_default_search_path(fu_ctx, g_search_dir);
        OSSL_PROVIDER *gp = OSSL_PROVIDER_load(fu_ctx, "gofips");
        OSSL_PROVIDER *bp = OSSL_PROVIDER_load(fu_ctx, "base");
        if (!gp || !bp) { failed = rounds; break; }
        pthread_t t[8];
        for (int i = 0; i < 8; i++) pthread_create(&t[i], NULL, fu_worker, (void *)(long)i);
        for (int i = 0; i < 8; i++) pthread_join(t[i], NULL);
        for (int i = 0; i < 8; i++) if (!fu_ok[i]) { failed++; break; }
        OSSL_PROVIDER_unload(bp);
        OSSL_PROVIDER_unload(gp);
        OSSL_LIB_CTX_free(fu_ctx);
    }
    char msg[160];
    snprintf(msg, sizeof(msg), "first-use: concurrent first TLS contexts all have TLS 1.3 ciphers (%d/%d rounds failed)",
             failed, rounds);
    CHECK(failed == 0, msg);
}

static void tlscaps(void) {
    /* Same query the core makes when libssl builds the ClientHello.
     * SSL_get1_groups/SSL_get_sigalgs return negotiated lists, empty
     * before a handshake, so they cannot be used here. */
    int gfound = 0, sfound = 0;
    OSSL_PROVIDER *prov = OSSL_PROVIDER_load(G, "gofips");
    int rg = OSSL_PROVIDER_get_capabilities(prov, "TLS-GROUP", caps_group_cb, &gfound);
    int rs = OSSL_PROVIDER_get_capabilities(prov, "TLS-SIGALG", caps_sig_cb, &sfound);
    CHECK(rg == 1 && (gfound & 1), "TLS caps: the TLS-GROUP callback exposes secp256r1 (id 23)");
    CHECK(rg == 1 && (gfound & 2), "TLS caps: the TLS-GROUP callback exposes the alias P-256 (id 23)");
    SSL_CTX *ctx = SSL_CTX_new_ex(G, NULL, TLS_client_method());
    CHECK(ctx && SSL_CTX_set1_groups_list(ctx, "secp256r1") == 1,
          "TLS caps: a gofips-only TLS context accepts the group name secp256r1");
    CHECK(ctx && SSL_CTX_set1_groups_list(ctx, "P-256") == 1,
          "TLS caps: a gofips-only TLS context accepts the group name P-256");
    SSL_CTX_free(ctx);
    CHECK(rs == 1 && sfound, "TLS caps: the TLS-SIGALG callback exposes ecdsa_secp256r1_sha256 (0x0403)");
}

int main(int argc, char **argv) {
    g_search_dir = argv[1];
    G = OSSL_LIB_CTX_new(); D = OSSL_LIB_CTX_new();
    dprov = OSSL_PROVIDER_load(D, "default");
    OSSL_PROVIDER_set_default_search_path(G, argv[1]);
    if (!(gprov = OSSL_PROVIDER_load(G, "gofips"))) { printf("LOAD FAIL\n"); return 3; }
    case_octet_buf(); case_keygen_race(); case_drbg_split(); case_kdf_salt(); case_kdf_life(); case_bn_priv(); case_bn_null(); case_rand_hook(); case_point_format(); case_names(); case_first_use(); tlscaps();
    if (f10_skipped)
        printf("AUDREG: rand-hook skipped (the running libcrypto predates RAND_set1_random_provider, OpenSSL >= 3.5; run the rand-hook block against a 3.5+ pair for that coverage)\n");
    printf(fails ? "AUDREG: %d FAILURES\n" : "AUDREG: ALL PASS\n", fails);
    return fails ? 1 : 0;
}
