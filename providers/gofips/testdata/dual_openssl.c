/* dual_openssl.c: OpenSSL 3 and OpenSSL 4 in one process, both with gofips
 * as their only cryptographic provider.
 *
 * The node images ship both libraries: Node links libcrypto.so.4, and
 * native modules built for OpenSSL 3 (Prisma's engines) link
 * libcrypto.so.3. Both read the same OPENSSL_CONF and load the same
 * gofips.so. This test loads each library by soname (dlopen, RTLD_LOCAL),
 * gives each its own library context with the gofips config, and checks:
 *
 *   1. per library: SHA-256 and SHA-384 known answers, HMAC-SHA256 (RFC
 *      4231 test case 4), MD5 unusable (no digest computed, and no
 *      provider but gofips answers for it), every digest a fetch returns
 *      served by gofips (Wolfi's OpenSSL 3.6 base also serves SHA-1 and
 *      MD5), a PEM private and public key load (base's decoders), and
 *      RAND_bytes_ex;
 *   2. the same checks from 4 threads per library, interleaved, 2000
 *      iterations each;
 *   3. the process maps exactly one gofips.so, and both libraries.
 *
 * It uses no OpenSSL headers: every function is resolved with dlsym from
 * the library under test, so neither ABI is assumed at compile time.
 *
 * Build:  cc -o dual_openssl dual_openssl.c -ldl -lpthread
 * Run:    GODEBUG=fips140=on ./dual_openssl <gofips config>
 *         (the config's module path names the gofips.so to load)
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef void *(*ctx_new_fn)(void);
typedef int (*load_config_fn)(void *, const char *);
typedef int (*q_digest_fn)(void *, const char *, const char *, const void *, size_t, unsigned char *, size_t *);
typedef unsigned char *(*q_mac_fn)(void *, const char *, const char *, const char *, const void *,
                                   const void *, size_t, const unsigned char *, size_t,
                                   unsigned char *, size_t, size_t *);
typedef void *(*md_fetch_fn)(void *, const char *, const char *);
typedef void (*md_free_fn)(void *);
typedef int (*rand_fn)(void *, unsigned char *, size_t, unsigned int);
typedef int (*prov_avail_fn)(void *, const char *);
typedef const void *(*md_prov_fn)(const void *);
typedef const char *(*prov_name_fn)(const void *);
typedef void *(*bio_mem_fn)(const void *, int);
typedef int (*bio_free_fn)(void *);
typedef void *(*pem_priv_fn)(void *, void **, void *, void *, void *, const char *);
typedef void *(*pem_pub_fn)(void *, void **, void *, void *, void *, const char *);
typedef void (*pkey_free_fn)(void *);

struct lib {
    const char *soname;
    void *dl, *ctx;
    q_digest_fn q_digest;
    q_mac_fn q_mac;
    md_fetch_fn md_fetch;
    md_free_fn md_free;
    rand_fn rand_bytes;
    prov_avail_fn prov_avail;
    md_prov_fn md_prov;
    prov_name_fn prov_name;
    bio_mem_fn bio_mem;
    bio_free_fn bio_free;
    pem_priv_fn pem_priv;
    pem_pub_fn pem_pub;
    pkey_free_fn pkey_free;
    volatile int fails;
};

static int fails;
#define CHECK(cond, ...) do { if (cond) { printf("PASS: " __VA_ARGS__); printf("\n"); } \
    else { printf("FAIL: " __VA_ARGS__); printf("\n"); fails++; } } while (0)

static const char *SHA256_ABC = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
static const char *SHA384_ABC = "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed"
                                "8086072ba1e7cc2358baeca134c825a7";
static const char *HMAC_TC4 = "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b";

static void hex(const unsigned char *b, size_t n, char *out) {
    for (size_t i = 0; i < n; i++) sprintf(out + 2 * i, "%02x", b[i]);
}

static int digest_ok(struct lib *l, const char *alg, const char *want) {
    unsigned char md[64]; size_t n = 0; char h[129];
    if (!l->q_digest(l->ctx, alg, NULL, "abc", 3, md, &n)) return 0;
    hex(md, n, h);
    return strcmp(h, want) == 0;
}

static int hmac_ok(struct lib *l) {
    unsigned char key[25], data[50], out[64]; size_t n = 0; char h[129];
    for (int i = 0; i < 25; i++) key[i] = (unsigned char)(i + 1);
    memset(data, 0xcd, sizeof data);
    if (!l->q_mac(l->ctx, "HMAC", NULL, "SHA2-256", NULL, key, sizeof key, data, sizeof data,
                  out, sizeof out, &n)) return 0;
    hex(out, n, h);
    return strcmp(h, HMAC_TC4) == 0;
}

/* MD5 is unusable: no digest is computed, and a fetch returns nothing or
 * gofips's refused MD5, never another provider's. */
static int md5_refused(struct lib *l) {
    unsigned char md[64]; size_t n = 0;
    if (l->q_digest(l->ctx, "MD5", NULL, "abc", 3, md, &n)) return 0;
    void *m = l->md_fetch(l->ctx, "MD5", NULL);
    if (!m) return 1;
    const char *name = l->prov_name(l->md_prov(m));
    int ok = name && strcmp(name, "gofips") == 0;
    l->md_free(m);
    return ok;
}

static const char *P256_PRIV =
    "-----BEGIN PRIVATE KEY-----\n"
    "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg0fE6DXb834FWBnYr\n"
    "00OBHWd5ECPMgCNbyeFr8J9yS3KhRANCAAT/DHVW+djze5iN9ZT0R6SBQ9l0smti\n"
    "KRUZVDUFLuO0z0ZijljsOn8NOJTep2gZGRJOlyMKxEsLdGhYWUXqIQOi\n"
    "-----END PRIVATE KEY-----\n";
static const char *P256_PUB =
    "-----BEGIN PUBLIC KEY-----\n"
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE/wx1VvnY83uYjfWU9EekgUPZdLJr\n"
    "YikVGVQ1BS7jtM9GYo5Y7Dp/DTiU3qdoGRkSTpcjCsRLC3RoWFlF6iEDog==\n"
    "-----END PUBLIC KEY-----\n";

/* PEM keys load: base's decoders are still found under the preference. */
static int pem_ok(struct lib *l) {
    int ok = 1;
    void *b = l->bio_mem(P256_PRIV, -1);
    void *k = b ? l->pem_priv(b, NULL, NULL, NULL, l->ctx, NULL) : NULL;
    ok &= k != NULL;
    if (k) l->pkey_free(k);
    if (b) l->bio_free(b);
    b = l->bio_mem(P256_PUB, -1);
    k = b ? l->pem_pub(b, NULL, NULL, NULL, l->ctx, NULL) : NULL;
    ok &= k != NULL;
    if (k) l->pkey_free(k);
    if (b) l->bio_free(b);
    return ok;
}

/* Every digest a fetch returns must be gofips's; a name not served is fine. */
static const char *DIGESTS[] = {"MD5", "MD4", "SHA1", "SHA2-224", "SHA2-256", "SHA2-384", "SHA2-512",
    "SHA2-512/224", "SHA2-512/256", "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512", "SHAKE128",
    "SHAKE256", "MD5-SHA1", "RIPEMD160", "SM3", "BLAKE2B-512", "BLAKE2S-256", "WHIRLPOOL", "MDC2", NULL};

static int digests_from_gofips(struct lib *l, const char **offender, const char **by) {
    for (int i = 0; DIGESTS[i]; i++) {
        void *md = l->md_fetch(l->ctx, DIGESTS[i], NULL);
        if (!md) continue;
        const char *name = l->prov_name(l->md_prov(md));
        int ok = name && strcmp(name, "gofips") == 0;
        if (!ok) { *offender = DIGESTS[i]; *by = name ? name : "?"; }
        l->md_free(md);
        if (!ok) return 0;
    }
    return 1;
}

static int rand_ok(struct lib *l) {
    unsigned char b[32] = {0}; int nz = 0;
    if (l->rand_bytes(l->ctx, b, sizeof b, 0) != 1) return 0;
    for (size_t i = 0; i < sizeof b; i++) nz |= b[i];
    return nz != 0;
}

static int load(struct lib *l, const char *conf) {
    l->dl = dlopen(l->soname, RTLD_NOW | RTLD_LOCAL);
    if (!l->dl) { printf("FAIL: dlopen %s: %s\n", l->soname, dlerror()); fails++; return 0; }
    ctx_new_fn ctx_new = (ctx_new_fn)dlsym(l->dl, "OSSL_LIB_CTX_new");
    load_config_fn load_config = (load_config_fn)dlsym(l->dl, "OSSL_LIB_CTX_load_config");
    l->q_digest = (q_digest_fn)dlsym(l->dl, "EVP_Q_digest");
    l->q_mac = (q_mac_fn)dlsym(l->dl, "EVP_Q_mac");
    l->md_fetch = (md_fetch_fn)dlsym(l->dl, "EVP_MD_fetch");
    l->md_free = (md_free_fn)dlsym(l->dl, "EVP_MD_free");
    l->rand_bytes = (rand_fn)dlsym(l->dl, "RAND_bytes_ex");
    l->prov_avail = (prov_avail_fn)dlsym(l->dl, "OSSL_PROVIDER_available");
    l->md_prov = (md_prov_fn)dlsym(l->dl, "EVP_MD_get0_provider");
    l->prov_name = (prov_name_fn)dlsym(l->dl, "OSSL_PROVIDER_get0_name");
    l->bio_mem = (bio_mem_fn)dlsym(l->dl, "BIO_new_mem_buf");
    l->bio_free = (bio_free_fn)dlsym(l->dl, "BIO_free");
    l->pem_priv = (pem_priv_fn)dlsym(l->dl, "PEM_read_bio_PrivateKey_ex");
    l->pem_pub = (pem_pub_fn)dlsym(l->dl, "PEM_read_bio_PUBKEY_ex");
    l->pkey_free = (pkey_free_fn)dlsym(l->dl, "EVP_PKEY_free");
    if (!ctx_new || !load_config || !l->q_digest || !l->q_mac || !l->md_fetch || !l->md_free ||
        !l->rand_bytes || !l->prov_avail || !l->md_prov || !l->prov_name || !l->bio_mem ||
        !l->bio_free || !l->pem_priv || !l->pem_pub || !l->pkey_free) {
        printf("FAIL: %s lacks a needed function\n", l->soname); fails++; return 0;
    }
    l->ctx = ctx_new();
    CHECK(l->ctx && load_config(l->ctx, conf) == 1, "%s: library context loads the gofips config", l->soname);
    CHECK(l->prov_avail(l->ctx, "gofips") == 1, "%s: gofips is available", l->soname);
    CHECK(l->prov_avail(l->ctx, "default") == 0, "%s: the default provider is not", l->soname);
    return l->ctx != NULL;
}

#define THREADS 4
#define ITERS 2000

static void *worker(void *arg) {
    struct lib *l = arg;
    for (int i = 0; i < ITERS; i++) {
        if (!digest_ok(l, "SHA2-256", SHA256_ABC) || !hmac_ok(l) || !md5_refused(l) || !rand_ok(l))
            __sync_fetch_and_add(&l->fails, 1);
    }
    return NULL;
}

static void maps_check(void) {
    FILE *f = fopen("/proc/self/maps", "r");
    char line[4096], gofips[4096] = "";
    int gofips_paths = 0, have3 = 0, have4 = 0;
    if (!f) { printf("FAIL: /proc/self/maps unreadable\n"); fails++; return; }
    while (fgets(line, sizeof line, f)) {
        char *p = strchr(line, '/');
        if (!p) continue;
        p[strcspn(p, "\n")] = 0;
        if (strstr(p, "gofips") && strstr(p, ".so")) {
            if (gofips[0] == 0) { snprintf(gofips, sizeof gofips, "%s", p); gofips_paths = 1; }
            else if (strcmp(p, gofips) != 0) gofips_paths++;
        }
        if (strstr(p, "libcrypto.so.3")) have3 = 1;
        if (strstr(p, "libcrypto.so.4")) have4 = 1;
    }
    fclose(f);
    CHECK(gofips_paths == 1, "one gofips.so is mapped (%s)", gofips);
    CHECK(have3 && have4, "libcrypto.so.3 and libcrypto.so.4 are both mapped");
}

int main(int argc, char **argv) {
    if (argc != 2) { fprintf(stderr, "usage: %s <gofips config>\n", argv[0]); return 2; }
    struct lib libs[2] = {{.soname = "libcrypto.so.3"}, {.soname = "libcrypto.so.4"}};
    for (int i = 0; i < 2; i++) {
        if (!load(&libs[i], argv[1])) continue;
        struct lib *l = &libs[i];
        CHECK(digest_ok(l, "SHA2-256", SHA256_ABC), "%s: SHA-256(\"abc\") known answer", l->soname);
        CHECK(digest_ok(l, "SHA2-384", SHA384_ABC), "%s: SHA-384(\"abc\") known answer", l->soname);
        CHECK(hmac_ok(l), "%s: HMAC-SHA256 RFC 4231 test case 4", l->soname);
        CHECK(md5_refused(l), "%s: MD5 cannot be used, and only gofips answers for it", l->soname);
        const char *off = NULL, *by = NULL;
        char why[128] = "";
        int from_gofips = digests_from_gofips(l, &off, &by);
        if (!from_gofips) snprintf(why, sizeof why, " (%s is served by %s)", off, by);
        CHECK(from_gofips, "%s: every digest served comes from gofips%s", l->soname, why);
        CHECK(pem_ok(l), "%s: a PEM private and public key load", l->soname);
        CHECK(rand_ok(l), "%s: RAND_bytes_ex returns random bytes", l->soname);
    }
    if (fails == 0) {
        pthread_t t[2 * THREADS];
        for (int i = 0; i < 2 * THREADS; i++) pthread_create(&t[i], NULL, worker, &libs[i % 2]);
        for (int i = 0; i < 2 * THREADS; i++) pthread_join(t[i], NULL);
        for (int i = 0; i < 2; i++)
            CHECK(libs[i].fails == 0, "%s: %d threads x %d iterations, interleaved with the other library (%d failed)",
                  libs[i].soname, THREADS, ITERS, libs[i].fails);
    }
    maps_check();
    if (fails) { printf("DUALOPENSSL: %d FAILED\n", fails); return 1; }
    printf("DUALOPENSSL: ALL PASS\n");
    return 0;
}
