/* dispatch.c, C-side OSSL_DISPATCH and OSSL_ALGORITHM tables for the
 * Temper gofips provider.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include "dispatch_abi_compat.h"

/* The tables must live in C: OSSL_DISPATCH.function is a C function pointer,
 * and cgo cannot take the address of an exported Go function from Go code.
 * The gofips_* symbols are the cgo exports of provider.go (declared extern
 * here; cgo emits them as real C symbols in the shared object).
 *
 * Function IDs follow OpenSSL 4.0.3 include/openssl/core_dispatch.h:
 *   provider-level: TEARDOWN=1024, GETTABLE_PARAMS=1025, GET_PARAMS=1026,
 *     QUERY_OPERATION=1027, UNQUERY_OPERATION=1028, GET_REASON_STRINGS=1029
 *   digest: NEWCTX=1, INIT=2, UPDATE=3, FINAL=4, FREECTX=6,
 *     GET_PARAMS=8, GET_CTX_PARAMS=10, SETTABLE_CTX_PARAMS=12,
 *     GETTABLE_CTX_PARAMS=13
 * Terminating entries use function==NULL / names==NULL.
 */
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>

/* cgo exports from provider.go (via _cgo_export.c at link time) */
extern void *gofips_digest_newctx(void *provctx);
extern void *gofips_digest_dupctx(void *src);
extern int gofips_digest_init(void *dctx, const OSSL_PARAM params[]);
extern int gofips_digest_update(void *dctx, const unsigned char *in, size_t inl);
extern int gofips_digest_final(void *dctx, unsigned char *out, size_t *outl, size_t outsz);
extern void gofips_digest_freectx(void *dctx);
extern int gofips_digest_get_params(OSSL_PARAM params[]);
extern const OSSL_PARAM *gofips_digest_gettable_params(OSSL_PARAM params[]);
extern int gofips_digest_get_ctx_params(void *dctx, OSSL_PARAM params[]);
extern int gofips_digest_set_ctx_params(void *dctx, const OSSL_PARAM params[]);
extern const OSSL_PARAM *gofips_digest_gettable_ctx_params(void *dctx, const OSSL_PARAM params[]);
extern const OSSL_PARAM *gofips_digest_settable_ctx_params(void *dctx, void *provctx);

extern void gofips_teardown(void *provctx);
extern int gofips_random_bytes(void *provctx, int which, void *buf, size_t n, unsigned int strength);
extern const OSSL_PARAM *gofips_gettable_params(void *provctx);
extern int gofips_get_params(void *provctx, OSSL_PARAM params[]);
extern const OSSL_ALGORITHM *gofips_query_operation(void *provctx, int operation_id, int *no_store);
extern void gofips_unquery_operation(void *provctx, int operation_id, const OSSL_ALGORITHM *alg);
extern const OSSL_ITEM *gofips_get_reason_strings(void *provctx);

/* TLS-SIGALG capability (ssl/t1_lib.c add_provider_sigalgs): one entry,
 * ecdsa_secp256r1_sha256 (0x0403). */
static const char *sigalg_iana = "ecdsa_secp256r1_sha256";
static const char *sigalg_name = "ECDSA";
static const char *sigalg_oid = "1.2.840.10045.4.3.2";
static const char *sigalg_signame = "ECDSA-SHA256";
static const char *sigalg_sigoid = "1.2.840.10045.4.3.2";
static const char *sigalg_hashname = "SHA2-256";
static const char *sigalg_hashoid = "2.16.840.1.101.3.4.2.1";
static const char *sigalg_keytype = "EC";
static const char *sigalg_keytypeoid = "1.2.840.10045.2.1";
static const unsigned int sigalg_codepoint = 0x0403;
static const unsigned int sigalg_secbits = 128;
static const int sigalg_mintls = 0x0304; /* TLS 1.3; TLS 1.2 uses libssl's built-in sigalg table */
static const int sigalg_maxtls = 0;
static const int sigalg_mindtls = -1;
static const int sigalg_maxdtls = -1;

static int gofips_tls_sigalg_capability(OSSL_CALLBACK *cb, void *cbarg) {
    OSSL_PARAM params[11];
    int n = 0;
    params[n].key = OSSL_CAPABILITY_TLS_SIGALG_IANA_NAME;
    params[n].data_type = OSSL_PARAM_UTF8_STRING;
    params[n].data = (void *)sigalg_iana;
    params[n].data_size = strlen(sigalg_iana) + 1;
    params[n].return_size = 0;
    n++;
    params[n].key = OSSL_CAPABILITY_TLS_SIGALG_NAME;
    params[n].data_type = OSSL_PARAM_UTF8_STRING;
    params[n].data = (void *)sigalg_name;
    params[n].data_size = strlen(sigalg_name) + 1;
    params[n].return_size = 0;
    n++;
    params[n].key = OSSL_CAPABILITY_TLS_SIGALG_OID;
    params[n].data_type = OSSL_PARAM_UTF8_STRING;
    params[n].data = (void *)sigalg_oid;
    params[n].data_size = strlen(sigalg_oid) + 1;
    params[n].return_size = 0;
    n++;
    params[n].key = OSSL_CAPABILITY_TLS_SIGALG_CODE_POINT;
    params[n].data_type = OSSL_PARAM_UNSIGNED_INTEGER;
    params[n].data = (void *)&sigalg_codepoint;
    params[n].data_size = sizeof(sigalg_codepoint);
    params[n].return_size = 0;
    n++;
    params[n].key = OSSL_CAPABILITY_TLS_SIGALG_SECURITY_BITS;
    params[n].data_type = OSSL_PARAM_UNSIGNED_INTEGER;
    params[n].data = (void *)&sigalg_secbits;
    params[n].data_size = sizeof(sigalg_secbits);
    params[n].return_size = 0;
    n++;
    params[n].key = OSSL_CAPABILITY_TLS_SIGALG_MIN_TLS;
    params[n].data_type = OSSL_PARAM_INTEGER;
    params[n].data = (void *)&sigalg_mintls;
    params[n].data_size = sizeof(sigalg_mintls);
    params[n].return_size = 0;
    n++;
    params[n].key = OSSL_CAPABILITY_TLS_SIGALG_MAX_TLS;
    params[n].data_type = OSSL_PARAM_INTEGER;
    params[n].data = (void *)&sigalg_maxtls;
    params[n].data_size = sizeof(sigalg_maxtls);
    params[n].return_size = 0;
    n++;
    params[n].key = OSSL_CAPABILITY_TLS_SIGALG_MIN_DTLS;
    params[n].data_type = OSSL_PARAM_INTEGER;
    params[n].data = (void *)&sigalg_mindtls;
    params[n].data_size = sizeof(sigalg_mindtls);
    params[n].return_size = 0;
    n++;
    params[n].key = OSSL_CAPABILITY_TLS_SIGALG_MAX_DTLS;
    params[n].data_type = OSSL_PARAM_INTEGER;
    params[n].data = (void *)&sigalg_maxdtls;
    params[n].data_size = sizeof(sigalg_maxdtls);
    params[n].return_size = 0;
    n++;
    params[n].key = OSSL_CAPABILITY_TLS_SIGALG_HASH_NAME;
    params[n].data_type = OSSL_PARAM_UTF8_STRING;
    params[n].data = (void *)sigalg_hashname;
    params[n].data_size = strlen(sigalg_hashname) + 1;
    params[n].return_size = 0;
    n++;
    params[n].key = NULL;
    params[n].data_type = 0;
    params[n].data = NULL;
    params[n].data_size = 0;
    params[n].return_size = 0;
    return cb(params, cbarg);
}

/* TLS-GROUP capability helper: emits the P-256 and P-384 group entries.
 * Pure C: the capability query may run during activation. */
int gofips_tls_group_capability(OSSL_CALLBACK *cb, void *cbarg);

static int gofips_tls_caps_c(void *provctx, const char *capability,
                             OSSL_CALLBACK *cb, void *cbarg) {
    (void)provctx;
    /* Diagnostic only: behind GOFIPS_DEBUG (read once at init via the
     * Go side's compiled-out debug flag; the C print here is gated on
     * the same env so release builds carry no unconditional stderr
     * noise). */
    if (getenv("GOFIPS_DEBUG") != NULL) {
        fprintf(stderr, "gofips: tls_caps query=%s\n", capability ? capability : "(null)");
    }
    if (cb == NULL || capability == NULL) return 0;
    if (strcmp(capability, "TLS-GROUP") == 0)
        return gofips_tls_group_capability(cb, cbarg);
    if (strcmp(capability, "TLS-SIGALG") == 0)
        return gofips_tls_sigalg_capability(cb, cbarg);
    return 0;
}

const OSSL_DISPATCH gofips_dispatch_table[] = {
    /* provider-level */
    {OSSL_FUNC_PROVIDER_TEARDOWN, (OSSL_FUNC)gofips_teardown},
    {OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (OSSL_FUNC)gofips_gettable_params},
    {OSSL_FUNC_PROVIDER_GET_PARAMS, (OSSL_FUNC)gofips_get_params},
    {OSSL_FUNC_PROVIDER_QUERY_OPERATION, (OSSL_FUNC)gofips_query_operation},
    {OSSL_FUNC_PROVIDER_UNQUERY_OPERATION, (OSSL_FUNC)gofips_unquery_operation},
    {OSSL_FUNC_PROVIDER_GET_REASON_STRINGS, (OSSL_FUNC)gofips_get_reason_strings},
    {OSSL_FUNC_PROVIDER_GET_CAPABILITIES, (OSSL_FUNC)gofips_tls_caps_c},
    {OSSL_FUNC_PROVIDER_RANDOM_BYTES, (OSSL_FUNC)gofips_random_bytes},
    /* digest operation */
    {OSSL_FUNC_DIGEST_NEWCTX, (OSSL_FUNC)gofips_digest_newctx},
    {OSSL_FUNC_DIGEST_INIT, (OSSL_FUNC)gofips_digest_init},
    {OSSL_FUNC_DIGEST_UPDATE, (OSSL_FUNC)gofips_digest_update},
    {OSSL_FUNC_DIGEST_FINAL, (OSSL_FUNC)gofips_digest_final},
    {OSSL_FUNC_DIGEST_FREECTX, (OSSL_FUNC)gofips_digest_freectx},
    {OSSL_FUNC_DIGEST_DUPCTX, (OSSL_FUNC)gofips_digest_dupctx},
    {OSSL_FUNC_DIGEST_GET_PARAMS, (OSSL_FUNC)gofips_digest_get_params},
    {OSSL_FUNC_DIGEST_GET_CTX_PARAMS, (OSSL_FUNC)gofips_digest_get_ctx_params},
    {OSSL_FUNC_DIGEST_SETTABLE_CTX_PARAMS, (OSSL_FUNC)gofips_digest_settable_ctx_params},
    {OSSL_FUNC_DIGEST_GETTABLE_CTX_PARAMS, (OSSL_FUNC)gofips_digest_gettable_ctx_params},
    /* gofips_digest_gettable_params is exported but not wired: it always
     * returns nil, and on OpenSSL 3.0.x a present-but-nil GETTABLE_PARAMS
     * entry breaks digest params handling where an absent entry does not
     * (the inventory counts it as exported-but-
     * unwired, a deliberate exemption, not an omission). */
    {0, NULL},
};

extern const OSSL_DISPATCH gofips_digest384_dispatch[];
extern const OSSL_DISPATCH gofips_digest512_dispatch[];

extern void *gofips_digest1_newctx(void *provctx);
extern void *gofips_digest1_dupctx(void *src);
extern int gofips_digest1_init(void *dctx, const OSSL_PARAM params[]);
extern int gofips_digest1_update(void *dctx, const unsigned char *in, size_t inl);
extern int gofips_digest1_final(void *dctx, unsigned char *out, size_t *outl, size_t outsz);
extern void gofips_digest1_freectx(void *dctx);
extern int gofips_digest1_get_params(OSSL_PARAM params[]);
extern int gofips_digest1_get_ctx_params(void *dctx, OSSL_PARAM params[]);
extern int gofips_digest1_set_ctx_params(void *dctx, const OSSL_PARAM params[]);
extern const OSSL_PARAM *gofips_digest1_gettable_ctx_params(void *dctx, const OSSL_PARAM params[]);
extern const OSSL_PARAM *gofips_digest1_settable_ctx_params(void *dctx, void *provctx);

const OSSL_DISPATCH gofips_digest1_dispatch[] = {
    {OSSL_FUNC_DIGEST_NEWCTX, (OSSL_FUNC)gofips_digest1_newctx},
    {OSSL_FUNC_DIGEST_INIT, (OSSL_FUNC)gofips_digest1_init},
    {OSSL_FUNC_DIGEST_UPDATE, (OSSL_FUNC)gofips_digest1_update},
    {OSSL_FUNC_DIGEST_FINAL, (OSSL_FUNC)gofips_digest1_final},
    {OSSL_FUNC_DIGEST_FREECTX, (OSSL_FUNC)gofips_digest1_freectx},
    {OSSL_FUNC_DIGEST_DUPCTX, (OSSL_FUNC)gofips_digest1_dupctx},
    {OSSL_FUNC_DIGEST_GET_PARAMS, (OSSL_FUNC)gofips_digest1_get_params},
    {OSSL_FUNC_DIGEST_GET_CTX_PARAMS, (OSSL_FUNC)gofips_digest1_get_ctx_params},
    {OSSL_FUNC_DIGEST_GETTABLE_CTX_PARAMS, (OSSL_FUNC)gofips_digest1_gettable_ctx_params},
    {OSSL_FUNC_DIGEST_SETTABLE_CTX_PARAMS, (OSSL_FUNC)gofips_digest1_settable_ctx_params},
    {0, NULL},
};

/* SHA-3 and SHAKE digest ops: one Go implementation (kdf_sha3.go); the
 * per-variant wrappers pass the variant (bit size, and xof for SHAKE). */
extern void *gofips_sha3_newctx(int variant, int xof);
extern int gofips_sha3_init(void *dctx, const OSSL_PARAM params[]);
extern int gofips_sha3_update(void *dctx, const unsigned char *in, size_t inl);
extern int gofips_sha3_final(void *dctx, unsigned char *out, size_t *outl, size_t outsz);
extern void *gofips_sha3_dupctx(void *src);
extern void gofips_sha3_freectx(void *dctx);
extern int gofips_sha3_get_params(int variant, int xof, OSSL_PARAM params[]);
extern int gofips_sha3_set_ctx_params(void *dctx, const OSSL_PARAM params[]);
extern const OSSL_PARAM *gofips_shake_settable_ctx_params(void *dctx, void *provctx);

const OSSL_PARAM gofips_shake_settable_ctx_params_tbl[] = {
    {OSSL_DIGEST_PARAM_XOFLEN, OSSL_PARAM_UNSIGNED_INTEGER, NULL, 0, 0},
    {NULL, 0, NULL, 0, 0},
};

static void *gofips_sha3_224_newctx(void *provctx) { (void)provctx; return gofips_sha3_newctx(224, 0); }
static int gofips_sha3_224_get_params(OSSL_PARAM params[]) { return gofips_sha3_get_params(224, 0, params); }
static void *gofips_sha3_256_newctx(void *provctx) { (void)provctx; return gofips_sha3_newctx(256, 0); }
static int gofips_sha3_256_get_params(OSSL_PARAM params[]) { return gofips_sha3_get_params(256, 0, params); }
static void *gofips_sha3_384_newctx(void *provctx) { (void)provctx; return gofips_sha3_newctx(384, 0); }
static int gofips_sha3_384_get_params(OSSL_PARAM params[]) { return gofips_sha3_get_params(384, 0, params); }
static void *gofips_sha3_512_newctx(void *provctx) { (void)provctx; return gofips_sha3_newctx(512, 0); }
static int gofips_sha3_512_get_params(OSSL_PARAM params[]) { return gofips_sha3_get_params(512, 0, params); }
static void *gofips_shake_128_newctx(void *provctx) { (void)provctx; return gofips_sha3_newctx(128, 1); }
static int gofips_shake_128_get_params(OSSL_PARAM params[]) { return gofips_sha3_get_params(128, 1, params); }
static void *gofips_shake_256_newctx(void *provctx) { (void)provctx; return gofips_sha3_newctx(256, 1); }
static int gofips_shake_256_get_params(OSSL_PARAM params[]) { return gofips_sha3_get_params(256, 1, params); }

const OSSL_DISPATCH gofips_sha3_224_dispatch[] = {
    {OSSL_FUNC_DIGEST_NEWCTX, (OSSL_FUNC)gofips_sha3_224_newctx},
    {OSSL_FUNC_DIGEST_INIT, (OSSL_FUNC)gofips_sha3_init},
    {OSSL_FUNC_DIGEST_UPDATE, (OSSL_FUNC)gofips_sha3_update},
    {OSSL_FUNC_DIGEST_FINAL, (OSSL_FUNC)gofips_sha3_final},
    {OSSL_FUNC_DIGEST_DUPCTX, (OSSL_FUNC)gofips_sha3_dupctx},
    {OSSL_FUNC_DIGEST_FREECTX, (OSSL_FUNC)gofips_sha3_freectx},
    {OSSL_FUNC_DIGEST_GET_PARAMS, (OSSL_FUNC)gofips_sha3_224_get_params},
    {0, NULL},
};

const OSSL_DISPATCH gofips_sha3_256_dispatch[] = {
    {OSSL_FUNC_DIGEST_NEWCTX, (OSSL_FUNC)gofips_sha3_256_newctx},
    {OSSL_FUNC_DIGEST_INIT, (OSSL_FUNC)gofips_sha3_init},
    {OSSL_FUNC_DIGEST_UPDATE, (OSSL_FUNC)gofips_sha3_update},
    {OSSL_FUNC_DIGEST_FINAL, (OSSL_FUNC)gofips_sha3_final},
    {OSSL_FUNC_DIGEST_DUPCTX, (OSSL_FUNC)gofips_sha3_dupctx},
    {OSSL_FUNC_DIGEST_FREECTX, (OSSL_FUNC)gofips_sha3_freectx},
    {OSSL_FUNC_DIGEST_GET_PARAMS, (OSSL_FUNC)gofips_sha3_256_get_params},
    {0, NULL},
};

const OSSL_DISPATCH gofips_sha3_384_dispatch[] = {
    {OSSL_FUNC_DIGEST_NEWCTX, (OSSL_FUNC)gofips_sha3_384_newctx},
    {OSSL_FUNC_DIGEST_INIT, (OSSL_FUNC)gofips_sha3_init},
    {OSSL_FUNC_DIGEST_UPDATE, (OSSL_FUNC)gofips_sha3_update},
    {OSSL_FUNC_DIGEST_FINAL, (OSSL_FUNC)gofips_sha3_final},
    {OSSL_FUNC_DIGEST_DUPCTX, (OSSL_FUNC)gofips_sha3_dupctx},
    {OSSL_FUNC_DIGEST_FREECTX, (OSSL_FUNC)gofips_sha3_freectx},
    {OSSL_FUNC_DIGEST_GET_PARAMS, (OSSL_FUNC)gofips_sha3_384_get_params},
    {0, NULL},
};

const OSSL_DISPATCH gofips_sha3_512_dispatch[] = {
    {OSSL_FUNC_DIGEST_NEWCTX, (OSSL_FUNC)gofips_sha3_512_newctx},
    {OSSL_FUNC_DIGEST_INIT, (OSSL_FUNC)gofips_sha3_init},
    {OSSL_FUNC_DIGEST_UPDATE, (OSSL_FUNC)gofips_sha3_update},
    {OSSL_FUNC_DIGEST_FINAL, (OSSL_FUNC)gofips_sha3_final},
    {OSSL_FUNC_DIGEST_DUPCTX, (OSSL_FUNC)gofips_sha3_dupctx},
    {OSSL_FUNC_DIGEST_FREECTX, (OSSL_FUNC)gofips_sha3_freectx},
    {OSSL_FUNC_DIGEST_GET_PARAMS, (OSSL_FUNC)gofips_sha3_512_get_params},
    {0, NULL},
};

const OSSL_DISPATCH gofips_shake_128_dispatch[] = {
    {OSSL_FUNC_DIGEST_NEWCTX, (OSSL_FUNC)gofips_shake_128_newctx},
    {OSSL_FUNC_DIGEST_INIT, (OSSL_FUNC)gofips_sha3_init},
    {OSSL_FUNC_DIGEST_UPDATE, (OSSL_FUNC)gofips_sha3_update},
    {OSSL_FUNC_DIGEST_FINAL, (OSSL_FUNC)gofips_sha3_final},
    {OSSL_FUNC_DIGEST_DUPCTX, (OSSL_FUNC)gofips_sha3_dupctx},
    {OSSL_FUNC_DIGEST_FREECTX, (OSSL_FUNC)gofips_sha3_freectx},
    {OSSL_FUNC_DIGEST_GET_PARAMS, (OSSL_FUNC)gofips_shake_128_get_params},
    {OSSL_FUNC_DIGEST_SET_CTX_PARAMS, (OSSL_FUNC)gofips_sha3_set_ctx_params},
    {OSSL_FUNC_DIGEST_SETTABLE_CTX_PARAMS, (OSSL_FUNC)gofips_shake_settable_ctx_params},
    {0, NULL},
};

const OSSL_DISPATCH gofips_shake_256_dispatch[] = {
    {OSSL_FUNC_DIGEST_NEWCTX, (OSSL_FUNC)gofips_shake_256_newctx},
    {OSSL_FUNC_DIGEST_INIT, (OSSL_FUNC)gofips_sha3_init},
    {OSSL_FUNC_DIGEST_UPDATE, (OSSL_FUNC)gofips_sha3_update},
    {OSSL_FUNC_DIGEST_FINAL, (OSSL_FUNC)gofips_sha3_final},
    {OSSL_FUNC_DIGEST_DUPCTX, (OSSL_FUNC)gofips_sha3_dupctx},
    {OSSL_FUNC_DIGEST_FREECTX, (OSSL_FUNC)gofips_sha3_freectx},
    {OSSL_FUNC_DIGEST_GET_PARAMS, (OSSL_FUNC)gofips_shake_256_get_params},
    {OSSL_FUNC_DIGEST_SET_CTX_PARAMS, (OSSL_FUNC)gofips_sha3_set_ctx_params},
    {OSSL_FUNC_DIGEST_SETTABLE_CTX_PARAMS, (OSSL_FUNC)gofips_shake_settable_ctx_params},
    {0, NULL},
};

const OSSL_ALGORITHM gofips_digest_algorithms[] = {
    /* Algorithm names here and below match the default provider's
     * (providers/implementations/include/prov/names.h). libssl fetches by
     * OBJ short name, e.g. "id-aes256-GCM"; a name the provider does not
     * register resolves only through libcrypto's lazily built name map,
     * which a concurrent first fetch can see incomplete. */
    {"SHA2-256:SHA-256:SHA256:2.16.840.1.101.3.4.2.1", "provider=gofips,fips=yes", gofips_dispatch_table,
     "SHA-256 (Go Cryptographic Module v1.0.0, CMVP #5247)"},
    /* SHA-1: served, and labelled not approved (fips=no; no certificate
     * reference in the description). The Go Cryptographic Module
     * (crypto/internal/fips140) contains no SHA-1, so this row runs
     * crypto/sha1, which is outside the validated module. It exists for
     * the non-security uses real applications cannot avoid: cache script
     * ids, WebSocket handshakes, ETags, version-5 UUIDs.
     *   - A fetch with "fips=yes" does not match this row and fails.
     *   - HMAC, HKDF, PBKDF2 and ECDSA do not accept SHA-1 (their digest
     *     lists are SHA-2 or SHA-3), so it cannot enter a MAC, KDF or
     *     signature.
     *   - Under GODEBUG=fips140=only Go itself refuses SHA-1; the fetch
     *     succeeds and the operation fails cleanly at init. */
    {"SHA1:SHA-1:SSL3-SHA1:1.3.14.3.2.26", "provider=gofips,fips=no", gofips_digest1_dispatch,
     "SHA-1 (NOT approved; outside the Go Cryptographic Module; non-security uses only)"},
    {"SHA2-384:SHA-384:SHA384:2.16.840.1.101.3.4.2.2", "provider=gofips,fips=yes", gofips_digest384_dispatch,
     "SHA-384 (Go Cryptographic Module v1.0.0, CMVP #5247)"},
    {"SHA2-512:SHA-512:SHA512:2.16.840.1.101.3.4.2.3", "provider=gofips,fips=yes", gofips_digest512_dispatch,
     "SHA-512 (Go Cryptographic Module v1.0.0, CMVP #5247)"},
    {"SHA3-224:2.16.840.1.101.3.4.2.7", "provider=gofips,fips=yes", gofips_sha3_224_dispatch,
     "SHA3-224 (Go Cryptographic Module v1.0.0, CMVP #5247)"},
    {"SHA3-256:2.16.840.1.101.3.4.2.8", "provider=gofips,fips=yes", gofips_sha3_256_dispatch,
     "SHA3-256 (Go Cryptographic Module v1.0.0, CMVP #5247)"},
    {"SHA3-384:2.16.840.1.101.3.4.2.9", "provider=gofips,fips=yes", gofips_sha3_384_dispatch,
     "SHA3-384 (Go Cryptographic Module v1.0.0, CMVP #5247)"},
    {"SHA3-512:2.16.840.1.101.3.4.2.10", "provider=gofips,fips=yes", gofips_sha3_512_dispatch,
     "SHA3-512 (Go Cryptographic Module v1.0.0, CMVP #5247)"},
    {"SHAKE-128:SHAKE128:2.16.840.1.101.3.4.2.11", "provider=gofips,fips=yes", gofips_shake_128_dispatch,
     "SHAKE-128 (Go Cryptographic Module v1.0.0, CMVP #5247)"},
    {"SHAKE-256:SHAKE256:2.16.840.1.101.3.4.2.12", "provider=gofips,fips=yes", gofips_shake_256_dispatch,
     "SHAKE-256 (Go Cryptographic Module v1.0.0, CMVP #5247)"},
    {NULL, NULL, NULL, NULL},
};

/* MD5, refused, for OpenSSL 3 cores only. Wolfi's OpenSSL 3.6 base
 * provider serves MD5 (and SHA-1) with properties "provider=base"; with
 * base active, MD5 would resolve there, outside the module. This row is
 * a complete digest, so the fetch succeeds and resolves to gofips under
 * the shipped config's "?provider=gofips" preference, and every entry
 * point fails: no context is created and nothing is computed. SHA-1
 * needs no row: gofips serves it, and the preference selects it over
 * base's. Under OpenSSL 4, whose base serves no digests, the row is not
 * registered and an MD5 fetch fails as before. */
extern int gofips_md5_refuse_get_params(OSSL_PARAM params[]);
static void *md5_refuse_newctx(void *provctx) { (void)provctx; return NULL; }
static void md5_refuse_freectx(void *dctx) { (void)dctx; }
static void *md5_refuse_dupctx(void *dctx) { (void)dctx; return NULL; }
static int md5_refuse_init(void *dctx, const OSSL_PARAM params[]) { (void)dctx; (void)params; return 0; }
static int md5_refuse_update(void *dctx, const unsigned char *in, size_t inl) { (void)dctx; (void)in; (void)inl; return 0; }
static int md5_refuse_final(void *dctx, unsigned char *out, size_t *outl, size_t outsz)
{
    (void)dctx; (void)out; (void)outsz;
    if (outl != NULL)
        *outl = 0;
    return 0;
}
static int md5_refuse_digest(void *provctx, const unsigned char *in, size_t inl,
                             unsigned char *out, size_t *outl, size_t outsz)
{
    (void)provctx; (void)in; (void)inl; (void)out; (void)outsz;
    if (outl != NULL)
        *outl = 0;
    return 0;
}
static const OSSL_DISPATCH gofips_md5_refuse_dispatch[] = {
    {OSSL_FUNC_DIGEST_NEWCTX, (OSSL_FUNC)md5_refuse_newctx},
    {OSSL_FUNC_DIGEST_INIT, (OSSL_FUNC)md5_refuse_init},
    {OSSL_FUNC_DIGEST_UPDATE, (OSSL_FUNC)md5_refuse_update},
    {OSSL_FUNC_DIGEST_FINAL, (OSSL_FUNC)md5_refuse_final},
    {OSSL_FUNC_DIGEST_DIGEST, (OSSL_FUNC)md5_refuse_digest},
    {OSSL_FUNC_DIGEST_FREECTX, (OSSL_FUNC)md5_refuse_freectx},
    {OSSL_FUNC_DIGEST_DUPCTX, (OSSL_FUNC)md5_refuse_dupctx},
    {OSSL_FUNC_DIGEST_GET_PARAMS, (OSSL_FUNC)gofips_md5_refuse_get_params},
    {0, NULL},
};

#define GOFIPS_N_DIGESTS (sizeof(gofips_digest_algorithms) / sizeof(gofips_digest_algorithms[0]) - 1)

/* gofips_digest_algorithms plus the refused MD5 row, for OpenSSL 3 cores. */
static OSSL_ALGORITHM gofips_digest_algorithms_ossl3[GOFIPS_N_DIGESTS + 2];
static pthread_once_t gofips_digest_ossl3_once = PTHREAD_ONCE_INIT;
static void gofips_digest_ossl3_build(void)
{
    memcpy(gofips_digest_algorithms_ossl3, gofips_digest_algorithms, GOFIPS_N_DIGESTS * sizeof(OSSL_ALGORITHM));
    gofips_digest_algorithms_ossl3[GOFIPS_N_DIGESTS] = (OSSL_ALGORITHM){
        "MD5:SSL3-MD5:1.2.840.113549.2.5", "provider=gofips,fips=no", gofips_md5_refuse_dispatch,
        "MD5 (refused: not served by gofips; registered so no other provider serves it)"};
    gofips_digest_algorithms_ossl3[GOFIPS_N_DIGESTS + 1] = (OSSL_ALGORITHM){NULL, NULL, NULL, NULL};
}
const OSSL_ALGORITHM *gofips_digest_table(int ossl3)
{
    if (!ossl3)
        return gofips_digest_algorithms;
    pthread_once(&gofips_digest_ossl3_once, gofips_digest_ossl3_build);
    return gofips_digest_algorithms_ossl3;
}

/* gofips_core_is_ossl3 reports whether the core loading the provider is
 * OpenSSL 3.x, from its OSSL_PROV_PARAM_CORE_VERSION. When the version
 * cannot be read it reports 1: registering the refused MD5 row is the
 * safe side. */
int gofips_core_is_ossl3(const OSSL_CORE_HANDLE *handle, const OSSL_DISPATCH *in)
{
    OSSL_FUNC_core_get_params_fn *get_params = NULL;
    for (; in != NULL && in->function_id != 0; in++) {
        if (in->function_id == OSSL_FUNC_CORE_GET_PARAMS)
            get_params = (OSSL_FUNC_core_get_params_fn *)in->function;
    }
    if (get_params == NULL)
        return 1;
    const char *version = NULL;
    OSSL_PARAM params[] = {
        {OSSL_PROV_PARAM_CORE_VERSION, OSSL_PARAM_UTF8_PTR, (void *)&version, sizeof(version), 0},
        {NULL, 0, NULL, 0, 0},
    };
    if (!get_params(handle, params) || version == NULL)
        return 1;
    return version[0] == '3' && version[1] == '.';
}

/* SHA-384 digest op (same ids as SHA-256 digest op) */

// Provider-level parameter type table, built here in C so the key strings
// are NUL-terminated C literals (Go string data is not NUL-terminated).
const OSSL_PARAM gofips_prov_param_types[] = {
    {OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, NULL, 0, 0},
    {OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR, NULL, 0, 0},
    {OSSL_PROV_PARAM_STATUS, OSSL_PARAM_UNSIGNED_INTEGER, NULL, 0, 0},
    {"temperfips-digestcalls", OSSL_PARAM_UNSIGNED_INTEGER, NULL, 0, 0},
    {"temperfips-randcalls", OSSL_PARAM_UNSIGNED_INTEGER, NULL, 0, 0},
    {"temperfips-ops", OSSL_PARAM_UTF8_PTR, NULL, 0, 0},
    {NULL, 0, NULL, 0, 0},
};

/* Reason strings: OpenSSL 3.5 provider_activate iterates this table without
 * a NULL check, so a provider returning NULL from get_reason_strings
 * segfaults activation. Provide a minimal terminated table. */
const OSSL_ITEM gofips_reason_strings[] = {
    {1, "temper gofips provider error strings"},
    {0, NULL},
};

/* HKDF settable ctx params: EVP_KDF_CTX_set_params validates each requested
 * param against this list; returning nil fails every derive. */
const OSSL_PARAM gofips_kdf_settable_ctx_params_tbl[] = {
    {OSSL_KDF_PARAM_DIGEST, OSSL_PARAM_UTF8_STRING, NULL, 0, 0},
    {OSSL_KDF_PARAM_KEY, OSSL_PARAM_OCTET_STRING, NULL, 0, 0},
    {OSSL_KDF_PARAM_SALT, OSSL_PARAM_OCTET_STRING, NULL, 0, 0},
    {OSSL_KDF_PARAM_INFO, OSSL_PARAM_OCTET_STRING, NULL, 0, 0},
    {OSSL_KDF_PARAM_DATA, OSSL_PARAM_OCTET_STRING, NULL, 0, 0},
    {OSSL_KDF_PARAM_MODE, OSSL_PARAM_INTEGER, NULL, 0, 0},
    {OSSL_KDF_PARAM_PREFIX, OSSL_PARAM_OCTET_STRING, NULL, 0, 0},
    {OSSL_KDF_PARAM_LABEL, OSSL_PARAM_OCTET_STRING, NULL, 0, 0},
    {NULL, 0, NULL, 0, 0},
};

/* HMAC settable ctx params: EVP_Q_mac checks for the 'digest' param here. */
const OSSL_PARAM gofips_mac_settable_ctx_params_tbl[] = {
    {OSSL_MAC_PARAM_DIGEST, OSSL_PARAM_UTF8_STRING, NULL, 0, 0},
    {OSSL_MAC_PARAM_KEY, OSSL_PARAM_OCTET_STRING, NULL, 0, 0},
    {OSSL_MAC_PARAM_SIZE, OSSL_PARAM_UNSIGNED_INTEGER, NULL, 0, 0},
    {NULL, 0, NULL, 0, 0},
};

/* HKDF gettable ctx params: SIZE, as the default provider's HKDF. */
const OSSL_PARAM gofips_kdf_gettable_ctx_params_tbl[] = {
    {OSSL_KDF_PARAM_SIZE, OSSL_PARAM_UNSIGNED_INTEGER, NULL, 0, 0},
    {NULL, 0, NULL, 0, 0},
};

/* RAND operation dispatch (OSSL_OP_RAND=5). RAND op function IDs (1-19)
 * per core_dispatch.h; the algorithm name CTR-DRBG matches what the core's
 * RAND machinery fetches when no default provider is active. */
extern void *gofips_rand_newctx(void *provctx, void *parent, const OSSL_DISPATCH *parent_calls);
extern void gofips_rand_freectx(void *vctx);
extern int gofips_rand_instantiate(void *vdrbg, unsigned int strength, int prediction_resistance, const unsigned char *pstr, size_t pstr_len, const OSSL_PARAM params[]);
extern int gofips_rand_uninstantiate(void *vdrbg);
extern int gofips_rand_generate(void *vctx, unsigned char *out, size_t outlen, unsigned int strength, int prediction_resistance, const unsigned char *addin, size_t addin_len);
extern int gofips_rand_reseed(void *vctx, int prediction_resistance, const unsigned char *ent, size_t ent_len, const unsigned char *addin, size_t addin_len);
extern int gofips_rand_enable_locking(void *vctx);
extern int gofips_rand_lock(void *vctx);
extern void gofips_rand_unlock(void *vctx);
extern int gofips_rand_get_ctx_params(void *vctx, OSSL_PARAM params[]);
extern int gofips_rand_set_ctx_params(void *vctx, const OSSL_PARAM params[]);
extern const OSSL_PARAM *gofips_rand_gettable_ctx_params(void *vctx, void *provctx);
extern const OSSL_PARAM *gofips_rand_settable_ctx_params(void *vctx, void *provctx);
extern int gofips_rand_verify_zeroization(void *vctx);

const OSSL_DISPATCH gofips_rand_dispatch[] = {
    {OSSL_FUNC_RAND_NEWCTX, (OSSL_FUNC)gofips_rand_newctx},
    {OSSL_FUNC_RAND_FREECTX, (OSSL_FUNC)gofips_rand_freectx},
    {OSSL_FUNC_RAND_INSTANTIATE, (OSSL_FUNC)gofips_rand_instantiate},
    {OSSL_FUNC_RAND_UNINSTANTIATE, (OSSL_FUNC)gofips_rand_uninstantiate},
    {OSSL_FUNC_RAND_GENERATE, (OSSL_FUNC)gofips_rand_generate},
    {OSSL_FUNC_RAND_RESEED, (OSSL_FUNC)gofips_rand_reseed},
    {OSSL_FUNC_RAND_ENABLE_LOCKING, (OSSL_FUNC)gofips_rand_enable_locking},
    {OSSL_FUNC_RAND_LOCK, (OSSL_FUNC)gofips_rand_lock},
    {OSSL_FUNC_RAND_UNLOCK, (OSSL_FUNC)gofips_rand_unlock},
    {OSSL_FUNC_RAND_GETTABLE_CTX_PARAMS, (OSSL_FUNC)gofips_rand_gettable_ctx_params},
    {OSSL_FUNC_RAND_SETTABLE_CTX_PARAMS, (OSSL_FUNC)gofips_rand_settable_ctx_params},
    {OSSL_FUNC_RAND_GET_CTX_PARAMS, (OSSL_FUNC)gofips_rand_get_ctx_params},
    {OSSL_FUNC_RAND_SET_CTX_PARAMS, (OSSL_FUNC)gofips_rand_set_ctx_params},
    {OSSL_FUNC_RAND_VERIFY_ZEROIZATION, (OSSL_FUNC)gofips_rand_verify_zeroization},
    {0, NULL},
};

const OSSL_ALGORITHM gofips_rand_algorithms[] = {
    {"CTR-DRBG", "provider=gofips", gofips_rand_dispatch,
     "Go crypto/rand: the module's SP 800-90A DRBG in FIPS mode; OpenSSL DRBG controls not forwarded (audit page 11)"},
    {NULL, NULL, NULL, NULL},
};

/* ---- TLS-surface helpers (tls.go) ---- */

/* Bridge for the keymgmt_export OSSL_CALLBACK: calls cb(params, cbarg). */
int gofips_call_param_cb(OSSL_CALLBACK *cb, void *cbarg, const OSSL_PARAM params[]) {
    if (cb == NULL) return 0;
    return cb(params, cbarg);
}

/* TLS-GROUP capability: P-256 and P-384, each under its TLS name and its
 * alias, as the default provider does. OpenSSL 4.0.3's group parser
 * requires: name, name-internal, id, alg, sec-bits, min-tls, max-tls. */
/* TLS-GROUP capability: one entry per group name. tlsname is the TLS-side
 * name: OpenSSL 4.0.3's TLS_DEFAULT_GROUP_LIST ("?*X25519:?secp256r1 / ...")
 * resolves names via tls1_group_name2id against tlsname/realname, and a
 * group advertised only as "prime256v1" is an unknown entry the '?' prefix
 * silently drops ('no suitable groups' at ClientHello). internal is the
 * keymgmt group name. algname is the keymgmt fetch name: t1_lib.c
 * EVP_KEYMGMT_fetch()s it to decide the group is usable ("ECDH" would fail
 * the fetch and drop the group). Each group is also listed under its
 * alias: without it, OpenSSL (3.x and 4.0) rejects "P-256" in a groups list
 * when gofips is the only EC provider. */
static const struct {
    const char *tlsname, *alias, *internal;
    unsigned int id, secbits;
} gofips_groups[] = {
    {"secp256r1", "P-256", "prime256v1", 23, 128},
    {"secp384r1", "P-384", "secp384r1", 24, 192},
};

static int gofips_tls_group(OSSL_CALLBACK *cb, void *cbarg, const char *name, const char *internal,
                            const unsigned int *id, const unsigned int *secbits) {
    static const char *algname = "EC";
    static const int mintls = 0x0303 /* TLS 1.2 */, maxtls = 0, nodtls = -1;
    OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_GROUP_NAME, (char *)name, 0),
        OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_GROUP_NAME_INTERNAL, (char *)internal, 0),
        OSSL_PARAM_uint(OSSL_CAPABILITY_TLS_GROUP_ID, (unsigned int *)id),
        OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_GROUP_ALG, (char *)algname, 0),
        OSSL_PARAM_uint(OSSL_CAPABILITY_TLS_GROUP_SECURITY_BITS, (unsigned int *)secbits),
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MIN_TLS, (int *)&mintls),
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MAX_TLS, (int *)&maxtls),
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MIN_DTLS, (int *)&nodtls),
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MAX_DTLS, (int *)&nodtls),
        OSSL_PARAM_END,
    };
    params[0].data_size = strlen(name) + 1;
    params[1].data_size = strlen(internal) + 1;
    params[3].data_size = strlen(algname) + 1;
    return cb(params, cbarg);
}

int gofips_tls_group_capability(OSSL_CALLBACK *cb, void *cbarg) {
    for (size_t i = 0; i < sizeof(gofips_groups) / sizeof(gofips_groups[0]); i++) {
        if (!gofips_tls_group(cb, cbarg, gofips_groups[i].tlsname, gofips_groups[i].internal,
                              &gofips_groups[i].id, &gofips_groups[i].secbits)
            || !gofips_tls_group(cb, cbarg, gofips_groups[i].alias, gofips_groups[i].internal,
                                 &gofips_groups[i].id, &gofips_groups[i].secbits))
            return 0;
    }
    return 1;
}

/* C-side param builders (NUL-terminated key strings). Returns the number of
 * params written to out[] (which must hold at least 3). */
int gofips_build_ec_export_params(OSSL_PARAM out[], const char *group, const unsigned char *pub, size_t publen,
                                  const unsigned char *priv, size_t privlen) {
    int n = 0;
    /* GROUP_NAME first: a cross-provider re-import (EVP_PKEY_fromdata
     * against the default provider) cannot build the EC group without
     * it (EC_GROUP_new_from_params: invalid field). */
    out[n].key = OSSL_PKEY_PARAM_GROUP_NAME;
    out[n].data_type = OSSL_PARAM_UTF8_STRING;
    out[n].data = (void *)group;
    out[n].data_size = strlen(group) + 1;
    out[n].return_size = 0;
    n++;
    if (pub != NULL) {
        out[n].key = OSSL_PKEY_PARAM_PUB_KEY;
        out[n].data_type = OSSL_PARAM_OCTET_STRING;
        out[n].data = (void *)pub;
        out[n].data_size = publen;
        out[n].return_size = 0;
        n++;
    }
    if (priv != NULL) {
        out[n].key = OSSL_PKEY_PARAM_PRIV_KEY;
        /* The private scalar is a BIGNUM, which OSSL_PARAM_get_BN reads
         * only from integer types. The Go side writes it little-endian,
         * the native integer order. */
        out[n].data_type = OSSL_PARAM_UNSIGNED_INTEGER;
        out[n].data = (void *)priv;
        out[n].data_size = privlen;
        out[n].return_size = 0;
        n++;
    }
    out[n].key = NULL;
    out[n].data_type = 0;
    out[n].data = NULL;
    out[n].data_size = 0;
    out[n].return_size = 0;
    return n;
}

/* EC keymgmt import/export/get param type tables (NUL-terminated C literals). */
const OSSL_PARAM gofips_ec_import_types[] = {
    {OSSL_PKEY_PARAM_PUB_KEY, OSSL_PARAM_OCTET_STRING, NULL, 0, 0},
    {OSSL_PKEY_PARAM_PRIV_KEY, OSSL_PARAM_OCTET_STRING, NULL, 0, 0},
    {OSSL_PKEY_PARAM_GROUP_NAME, OSSL_PARAM_UTF8_STRING, NULL, 0, 0},
    {NULL, 0, NULL, 0, 0},
};

const OSSL_PARAM gofips_ec_export_types[] = {
    {OSSL_PKEY_PARAM_PUB_KEY, OSSL_PARAM_OCTET_STRING, NULL, 0, 0},
    /* the scalar is emitted as an integer param (OSSL_PARAM_get_BN's
     * required type); octet-string export of a BIGNUM fails re-import */
    {OSSL_PKEY_PARAM_PRIV_KEY, OSSL_PARAM_UNSIGNED_INTEGER, NULL, 0, 0},
    {NULL, 0, NULL, 0, 0},
};

const OSSL_PARAM gofips_ec_keymgmt_params[] = {
    {OSSL_PKEY_PARAM_GROUP_NAME, OSSL_PARAM_UTF8_STRING, NULL, 0, 0},
    {OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT, OSSL_PARAM_UTF8_STRING, NULL, 0, 0},
    {OSSL_PKEY_PARAM_MAX_SIZE, OSSL_PARAM_UNSIGNED_INTEGER, NULL, 0, 0},
    {OSSL_PKEY_PARAM_EC_DECODED_FROM_EXPLICIT_PARAMS, OSSL_PARAM_INTEGER, NULL, 0, 0},
    {OSSL_PKEY_PARAM_DEFAULT_DIGEST, OSSL_PARAM_UTF8_STRING, NULL, 0, 0},
    {NULL, 0, NULL, 0, 0},
};

/* ---- TLS-surface dispatch tables (ids per core_dispatch.h) ---- */

/* SHA-384 digest op (same ids as SHA-256 digest op) */
extern void *gofips_digest384_newctx(void *provctx);
extern void *gofips_digest384_dupctx(void *src);
extern int gofips_digest384_init(void *dctx, const OSSL_PARAM params[]);
extern int gofips_digest384_update(void *dctx, const unsigned char *in, size_t inl);
extern int gofips_digest384_final(void *dctx, unsigned char *out, size_t *outl, size_t outsz);
extern void gofips_digest384_freectx(void *dctx);
extern int gofips_digest384_get_params(OSSL_PARAM params[]);
extern int gofips_digest384_get_ctx_params(void *dctx, OSSL_PARAM params[]);
extern int gofips_digest384_set_ctx_params(void *dctx, const OSSL_PARAM params[]);
extern const OSSL_PARAM *gofips_digest384_gettable_ctx_params(void *dctx, const OSSL_PARAM params[]);
extern const OSSL_PARAM *gofips_digest384_settable_ctx_params(void *dctx, void *provctx);

const OSSL_DISPATCH gofips_digest384_dispatch[] = {
    {OSSL_FUNC_DIGEST_NEWCTX, (OSSL_FUNC)gofips_digest384_newctx},
    {OSSL_FUNC_DIGEST_INIT, (OSSL_FUNC)gofips_digest384_init},
    {OSSL_FUNC_DIGEST_UPDATE, (OSSL_FUNC)gofips_digest384_update},
    {OSSL_FUNC_DIGEST_FINAL, (OSSL_FUNC)gofips_digest384_final},
    {OSSL_FUNC_DIGEST_FREECTX, (OSSL_FUNC)gofips_digest384_freectx},
    {OSSL_FUNC_DIGEST_DUPCTX, (OSSL_FUNC)gofips_digest384_dupctx},
    {OSSL_FUNC_DIGEST_GET_PARAMS, (OSSL_FUNC)gofips_digest384_get_params},
    {OSSL_FUNC_DIGEST_GET_CTX_PARAMS, (OSSL_FUNC)gofips_digest384_get_ctx_params},
    {OSSL_FUNC_DIGEST_GETTABLE_CTX_PARAMS, (OSSL_FUNC)gofips_digest384_gettable_ctx_params},
    {OSSL_FUNC_DIGEST_SETTABLE_CTX_PARAMS, (OSSL_FUNC)gofips_digest384_settable_ctx_params},
    {0, NULL},
};



/* HMAC MAC op */
extern void *gofips_mac_newctx(void *provctx);
extern void *gofips_mac_dupctx(void *src);
extern void gofips_mac_freectx(void *mctx);
extern int gofips_mac_init(void *mctx, const unsigned char *key, size_t keylen, const OSSL_PARAM params[]);
extern int gofips_mac_update(void *mctx, const unsigned char *in, size_t inl);
extern int gofips_mac_final(void *mctx, unsigned char *out, size_t *outl, size_t outsz);
extern int gofips_mac_get_params(OSSL_PARAM params[]);
extern int gofips_mac_get_ctx_params(void *mctx, OSSL_PARAM params[]);
extern int gofips_mac_set_ctx_params(void *mctx, const OSSL_PARAM params[]);
extern const OSSL_PARAM *gofips_mac_gettable_params(void *provctx);
extern const OSSL_PARAM *gofips_mac_gettable_ctx_params(void *mctx, void *provctx);
extern const OSSL_PARAM *gofips_mac_settable_ctx_params(void *mctx, void *provctx);

const OSSL_DISPATCH gofips_mac_dispatch[] = {
    {OSSL_FUNC_MAC_NEWCTX, (OSSL_FUNC)gofips_mac_newctx},
    {OSSL_FUNC_MAC_DUPCTX, (OSSL_FUNC)gofips_mac_dupctx},
    {OSSL_FUNC_MAC_FREECTX, (OSSL_FUNC)gofips_mac_freectx},
    {OSSL_FUNC_MAC_INIT, (OSSL_FUNC)gofips_mac_init},
    {OSSL_FUNC_MAC_UPDATE, (OSSL_FUNC)gofips_mac_update},
    {OSSL_FUNC_MAC_FINAL, (OSSL_FUNC)gofips_mac_final},
    {OSSL_FUNC_MAC_GET_PARAMS, (OSSL_FUNC)gofips_mac_get_params},
    {OSSL_FUNC_MAC_GET_CTX_PARAMS, (OSSL_FUNC)gofips_mac_get_ctx_params},
    {OSSL_FUNC_MAC_SET_CTX_PARAMS, (OSSL_FUNC)gofips_mac_set_ctx_params},
    {OSSL_FUNC_MAC_GETTABLE_PARAMS, (OSSL_FUNC)gofips_mac_gettable_params},
    {OSSL_FUNC_MAC_GETTABLE_CTX_PARAMS, (OSSL_FUNC)gofips_mac_gettable_ctx_params},
    {OSSL_FUNC_MAC_SETTABLE_CTX_PARAMS, (OSSL_FUNC)gofips_mac_settable_ctx_params},
    {0, NULL},
};

const OSSL_ALGORITHM gofips_mac_algorithms[] = {
    {"HMAC", "provider=gofips,fips=yes", gofips_mac_dispatch,
     "HMAC-SHA2 (Go Cryptographic Module v1.0.0, CMVP #5247)"},
    {NULL, NULL, NULL, NULL},
};

/* HKDF KDF op */
extern void *gofips_kdf_newctx(void *provctx);
extern void *gofips_kdf_dupctx(void *src);
extern void gofips_kdf_freectx(void *kctx);
extern void gofips_kdf_reset(void *kctx);
extern int gofips_kdf_derive(void *kctx, unsigned char *key, size_t keylen, const OSSL_PARAM params[]);
extern int gofips_kdf_set_ctx_params(void *kctx, const OSSL_PARAM params[]);
extern const OSSL_PARAM *gofips_kdf_gettable_ctx_params(void *kctx, void *provctx);
extern const OSSL_PARAM *gofips_kdf_settable_ctx_params(void *kctx, void *provctx);
extern int gofips_kdf_get_ctx_params(void *kctx, OSSL_PARAM params[]);
extern const OSSL_PARAM *gofips_kdf_gettable_params(void *provctx);
extern int gofips_kdf_get_params(OSSL_PARAM params[]);

const OSSL_DISPATCH gofips_kdf_dispatch[] = {
    {OSSL_FUNC_KDF_NEWCTX, (OSSL_FUNC)gofips_kdf_newctx},
    {OSSL_FUNC_KDF_DUPCTX, (OSSL_FUNC)gofips_kdf_dupctx},
    {OSSL_FUNC_KDF_FREECTX, (OSSL_FUNC)gofips_kdf_freectx},
    {OSSL_FUNC_KDF_RESET, (OSSL_FUNC)gofips_kdf_reset},
    {OSSL_FUNC_KDF_DERIVE, (OSSL_FUNC)gofips_kdf_derive},
    {OSSL_FUNC_KDF_GETTABLE_PARAMS, (OSSL_FUNC)gofips_kdf_gettable_params},
    {OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS, (OSSL_FUNC)gofips_kdf_gettable_ctx_params},
    {OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS, (OSSL_FUNC)gofips_kdf_settable_ctx_params},
    {OSSL_FUNC_KDF_GET_PARAMS, (OSSL_FUNC)gofips_kdf_get_params},
    {OSSL_FUNC_KDF_GET_CTX_PARAMS, (OSSL_FUNC)gofips_kdf_get_ctx_params},
    {OSSL_FUNC_KDF_SET_CTX_PARAMS, (OSSL_FUNC)gofips_kdf_set_ctx_params},
    {0, NULL},
};

extern const OSSL_DISPATCH gofips_tls13kdf_dispatch[];
extern const OSSL_ALGORITHM gofips_tls13kdf_algorithms[];

/* PBKDF2 KDF op (kdf_sha3.go) */
extern void *gofips_pbkdf2_newctx(void *provctx);
extern void *gofips_pbkdf2_dupctx(void *src);
extern void gofips_pbkdf2_freectx(void *kctx);
extern void gofips_pbkdf2_reset(void *kctx);
extern int gofips_pbkdf2_derive(void *kctx, unsigned char *key, size_t keylen, const OSSL_PARAM params[]);
extern int gofips_pbkdf2_set_ctx_params(void *kctx, const OSSL_PARAM params[]);
extern const OSSL_PARAM *gofips_pbkdf2_settable_ctx_params(void *kctx, void *provctx);
extern const OSSL_PARAM *gofips_pbkdf2_gettable_ctx_params(void *kctx, void *provctx);
extern int gofips_pbkdf2_get_ctx_params(void *kctx, OSSL_PARAM params[]);

const OSSL_PARAM gofips_pbkdf2_settable_ctx_params_tbl[] = {
    {OSSL_KDF_PARAM_PASSWORD, OSSL_PARAM_OCTET_STRING, NULL, 0, 0},
    {OSSL_KDF_PARAM_SALT, OSSL_PARAM_OCTET_STRING, NULL, 0, 0},
    {OSSL_KDF_PARAM_ITER, OSSL_PARAM_UNSIGNED_INTEGER, NULL, 0, 0},
    {OSSL_KDF_PARAM_DIGEST, OSSL_PARAM_UTF8_STRING, NULL, 0, 0},
    {OSSL_KDF_PARAM_PROPERTIES, OSSL_PARAM_UTF8_STRING, NULL, 0, 0},
    {OSSL_KDF_PARAM_PKCS5, OSSL_PARAM_INTEGER, NULL, 0, 0},
    {NULL, 0, NULL, 0, 0},
};

const OSSL_PARAM gofips_pbkdf2_gettable_ctx_params_tbl[] = {
    {OSSL_KDF_PARAM_SIZE, OSSL_PARAM_UNSIGNED_INTEGER, NULL, 0, 0},
    {NULL, 0, NULL, 0, 0},
};

const OSSL_DISPATCH gofips_pbkdf2_dispatch[] = {
    {OSSL_FUNC_KDF_NEWCTX, (OSSL_FUNC)gofips_pbkdf2_newctx},
    {OSSL_FUNC_KDF_DUPCTX, (OSSL_FUNC)gofips_pbkdf2_dupctx},
    {OSSL_FUNC_KDF_FREECTX, (OSSL_FUNC)gofips_pbkdf2_freectx},
    {OSSL_FUNC_KDF_RESET, (OSSL_FUNC)gofips_pbkdf2_reset},
    {OSSL_FUNC_KDF_DERIVE, (OSSL_FUNC)gofips_pbkdf2_derive},
    {OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS, (OSSL_FUNC)gofips_pbkdf2_settable_ctx_params},
    {OSSL_FUNC_KDF_SET_CTX_PARAMS, (OSSL_FUNC)gofips_pbkdf2_set_ctx_params},
    {OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS, (OSSL_FUNC)gofips_pbkdf2_gettable_ctx_params},
    {OSSL_FUNC_KDF_GET_CTX_PARAMS, (OSSL_FUNC)gofips_pbkdf2_get_ctx_params},
    {0, NULL},
};

/* TLS1-PRF: the TLS 1.2 KDF (tls12.go) */
extern void *gofips_tls1prf_newctx(void *provctx);
extern void *gofips_tls1prf_dupctx(void *src);
extern void gofips_tls1prf_freectx(void *kctx);
extern void gofips_tls1prf_reset(void *kctx);
extern int gofips_tls1prf_derive(void *kctx, unsigned char *key, size_t keylen, const OSSL_PARAM params[]);
extern int gofips_tls1prf_set_ctx_params(void *kctx, const OSSL_PARAM params[]);
extern const OSSL_PARAM *gofips_tls1prf_settable_ctx_params(void *kctx, void *provctx);
extern const OSSL_PARAM *gofips_tls1prf_gettable_ctx_params(void *kctx, void *provctx);
extern int gofips_tls1prf_get_ctx_params(void *kctx, OSSL_PARAM params[]);

const OSSL_PARAM gofips_tls1prf_settable_ctx_params_tbl[] = {
    {OSSL_KDF_PARAM_DIGEST, OSSL_PARAM_UTF8_STRING, NULL, 0, 0},
    {OSSL_KDF_PARAM_SECRET, OSSL_PARAM_OCTET_STRING, NULL, 0, 0},
    {OSSL_KDF_PARAM_SEED, OSSL_PARAM_OCTET_STRING, NULL, 0, 0},
    {"ems_check", OSSL_PARAM_INTEGER, NULL, 0, 0}, /* OSSL_KDF_PARAM_FIPS_EMS_CHECK, 3.4+ */
    {NULL, 0, NULL, 0, 0},
};

const OSSL_PARAM gofips_tls1prf_gettable_ctx_params_tbl[] = {
    {OSSL_KDF_PARAM_SIZE, OSSL_PARAM_UNSIGNED_INTEGER, NULL, 0, 0},
    {NULL, 0, NULL, 0, 0},
};

const OSSL_DISPATCH gofips_tls1prf_dispatch[] = {
    {OSSL_FUNC_KDF_NEWCTX, (OSSL_FUNC)gofips_tls1prf_newctx},
    {OSSL_FUNC_KDF_DUPCTX, (OSSL_FUNC)gofips_tls1prf_dupctx},
    {OSSL_FUNC_KDF_FREECTX, (OSSL_FUNC)gofips_tls1prf_freectx},
    {OSSL_FUNC_KDF_RESET, (OSSL_FUNC)gofips_tls1prf_reset},
    {OSSL_FUNC_KDF_DERIVE, (OSSL_FUNC)gofips_tls1prf_derive},
    {OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS, (OSSL_FUNC)gofips_tls1prf_settable_ctx_params},
    {OSSL_FUNC_KDF_SET_CTX_PARAMS, (OSSL_FUNC)gofips_tls1prf_set_ctx_params},
    {OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS, (OSSL_FUNC)gofips_tls1prf_gettable_ctx_params},
    {OSSL_FUNC_KDF_GET_CTX_PARAMS, (OSSL_FUNC)gofips_tls1prf_get_ctx_params},
    {0, NULL},
};

const OSSL_ALGORITHM gofips_kdf_algorithms[] = {
    {"HKDF", "provider=gofips,fips=yes", gofips_kdf_dispatch,
     "HKDF-SHA2 (Go Cryptographic Module v1.0.0, CMVP #5247)"},
    {"PBKDF2:1.2.840.113549.1.5.12", "provider=gofips,fips=yes", gofips_pbkdf2_dispatch,
     "PBKDF2 (SP 800-132; Go Cryptographic Module v1.0.0, CMVP #5247)"},
    {"TLS13-KDF", "provider=gofips,fips=yes", gofips_tls13kdf_dispatch,
     "TLS 1.3 key-schedule KDF: module HKDF service (crypto/hkdf, CMVP #5247) plus RFC 8446 section 7.1 label framing; not a separate TLS13-KDF service row"},
    {"TLS1-PRF", "provider=gofips,fips=yes", gofips_tls1prf_dispatch,
     "TLS 1.2 KDF, SP 800-135, SHA-256/384/512, extended master secret required (Go Cryptographic Module v1.0.0, CMVP #5247)"},
    {NULL, NULL, NULL, NULL},
};

/* AES-GCM cipher op (one-shot model; update buffers, final seals/opens) */
extern void *gofips_cipher_newctx(void *provctx);
extern void gofips_cipher_freectx(void *cctx);
extern void *gofips_cipher_dupctx(void *cctx);
extern int gofips_cipher_encrypt_init(void *cctx, const unsigned char *key, size_t keylen, const unsigned char *iv, size_t ivlen, const OSSL_PARAM params[]);
extern int gofips_cipher_decrypt_init(void *cctx, const unsigned char *key, size_t keylen, const unsigned char *iv, size_t ivlen, const OSSL_PARAM params[]);
extern int gofips_cipher_update(void *cctx, unsigned char *out, size_t *outl, size_t outsize, const unsigned char *in, size_t inl);
extern int gofips_cipher_final(void *cctx, unsigned char *out, size_t *outl, size_t outsize);
extern int gofips_cipher_cipher(void *cctx, unsigned char *out, size_t *outl, size_t outsize, const unsigned char *in, size_t inl);
extern int gofips_cipher_get_params(OSSL_PARAM params[]);
extern int gofips_cipher_get_ctx_params(void *cctx, OSSL_PARAM params[]);
extern int gofips_cipher_set_ctx_params(void *cctx, const OSSL_PARAM params[]);
extern const OSSL_PARAM *gofips_cipher_gettable_params(void *provctx);
extern const OSSL_PARAM *gofips_cipher_gettable_ctx_params(void *cctx, void *provctx);
extern const OSSL_PARAM *gofips_cipher_settable_ctx_params(void *cctx, void *provctx);

const OSSL_DISPATCH gofips_cipher_dispatch[] = {
    {OSSL_FUNC_CIPHER_NEWCTX, (OSSL_FUNC)gofips_cipher_newctx},
    {OSSL_FUNC_CIPHER_FREECTX, (OSSL_FUNC)gofips_cipher_freectx},
    {OSSL_FUNC_CIPHER_DUPCTX, (OSSL_FUNC)gofips_cipher_dupctx},
    {OSSL_FUNC_CIPHER_ENCRYPT_INIT, (OSSL_FUNC)gofips_cipher_encrypt_init},
    {OSSL_FUNC_CIPHER_DECRYPT_INIT, (OSSL_FUNC)gofips_cipher_decrypt_init},
    {OSSL_FUNC_CIPHER_UPDATE, (OSSL_FUNC)gofips_cipher_update},
    {OSSL_FUNC_CIPHER_FINAL, (OSSL_FUNC)gofips_cipher_final},
    {OSSL_FUNC_CIPHER_CIPHER, (OSSL_FUNC)gofips_cipher_cipher},
    {OSSL_FUNC_CIPHER_GET_PARAMS, (OSSL_FUNC)gofips_cipher_get_params},
    {OSSL_FUNC_CIPHER_GET_CTX_PARAMS, (OSSL_FUNC)gofips_cipher_get_ctx_params},
    {OSSL_FUNC_CIPHER_SET_CTX_PARAMS, (OSSL_FUNC)gofips_cipher_set_ctx_params},
    {OSSL_FUNC_CIPHER_GETTABLE_PARAMS, (OSSL_FUNC)gofips_cipher_gettable_params},
    {OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS, (OSSL_FUNC)gofips_cipher_gettable_ctx_params},
    {OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS, (OSSL_FUNC)gofips_cipher_settable_ctx_params},
    {0, NULL},
};

extern void *gofips_cbc_newctx(void *provctx);
extern void gofips_cbc_freectx(void *cctx);
extern void *gofips_cbc_dupctx(void *cctx);
extern int gofips_cbc_get_params(OSSL_PARAM params[]);

const OSSL_DISPATCH gofips_cbc_dispatch[] = {
    {OSSL_FUNC_CIPHER_NEWCTX, (OSSL_FUNC)gofips_cbc_newctx},
    {OSSL_FUNC_CIPHER_FREECTX, (OSSL_FUNC)gofips_cbc_freectx},
    {OSSL_FUNC_CIPHER_DUPCTX, (OSSL_FUNC)gofips_cbc_dupctx},
    {OSSL_FUNC_CIPHER_ENCRYPT_INIT, (OSSL_FUNC)gofips_cipher_encrypt_init},
    {OSSL_FUNC_CIPHER_DECRYPT_INIT, (OSSL_FUNC)gofips_cipher_decrypt_init},
    {OSSL_FUNC_CIPHER_UPDATE, (OSSL_FUNC)gofips_cipher_update},
    {OSSL_FUNC_CIPHER_FINAL, (OSSL_FUNC)gofips_cipher_final},
    {OSSL_FUNC_CIPHER_CIPHER, (OSSL_FUNC)gofips_cipher_cipher},
    {OSSL_FUNC_CIPHER_GET_PARAMS, (OSSL_FUNC)gofips_cbc_get_params},
    {OSSL_FUNC_CIPHER_GET_CTX_PARAMS, (OSSL_FUNC)gofips_cipher_get_ctx_params},
    {OSSL_FUNC_CIPHER_SET_CTX_PARAMS, (OSSL_FUNC)gofips_cipher_set_ctx_params},
    {OSSL_FUNC_CIPHER_GETTABLE_PARAMS, (OSSL_FUNC)gofips_cipher_gettable_params},
    {OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS, (OSSL_FUNC)gofips_cipher_gettable_ctx_params},
    {OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS, (OSSL_FUNC)gofips_cipher_settable_ctx_params},
    {0, NULL},
};

extern void *gofips_cbc128_newctx(void *provctx);
extern int gofips_cbc128_get_params(OSSL_PARAM params[]);

const OSSL_DISPATCH gofips_cbc128_dispatch[] = {
    {OSSL_FUNC_CIPHER_NEWCTX, (OSSL_FUNC)gofips_cbc128_newctx},
    {OSSL_FUNC_CIPHER_FREECTX, (OSSL_FUNC)gofips_cbc_freectx},
    {OSSL_FUNC_CIPHER_DUPCTX, (OSSL_FUNC)gofips_cbc_dupctx},
    {OSSL_FUNC_CIPHER_ENCRYPT_INIT, (OSSL_FUNC)gofips_cipher_encrypt_init},
    {OSSL_FUNC_CIPHER_DECRYPT_INIT, (OSSL_FUNC)gofips_cipher_decrypt_init},
    {OSSL_FUNC_CIPHER_UPDATE, (OSSL_FUNC)gofips_cipher_update},
    {OSSL_FUNC_CIPHER_FINAL, (OSSL_FUNC)gofips_cipher_final},
    {OSSL_FUNC_CIPHER_CIPHER, (OSSL_FUNC)gofips_cipher_cipher},
    {OSSL_FUNC_CIPHER_GET_PARAMS, (OSSL_FUNC)gofips_cbc128_get_params},
    {OSSL_FUNC_CIPHER_GET_CTX_PARAMS, (OSSL_FUNC)gofips_cipher_get_ctx_params},
    {OSSL_FUNC_CIPHER_SET_CTX_PARAMS, (OSSL_FUNC)gofips_cipher_set_ctx_params},
    {OSSL_FUNC_CIPHER_GETTABLE_PARAMS, (OSSL_FUNC)gofips_cipher_gettable_params},
    {OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS, (OSSL_FUNC)gofips_cipher_gettable_ctx_params},
    {OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS, (OSSL_FUNC)gofips_cipher_settable_ctx_params},
    {0, NULL},
};

extern int gofips_cipher128_get_params(OSSL_PARAM params[]);
extern void *gofips_cipher128_newctx(void *provctx);
extern void gofips_cipher128_freectx(void *cctx);
extern void *gofips_cipher128_dupctx(void *cctx);

const OSSL_DISPATCH gofips_cipher128_dispatch[] = {
    {OSSL_FUNC_CIPHER_NEWCTX, (OSSL_FUNC)gofips_cipher128_newctx},
    {OSSL_FUNC_CIPHER_FREECTX, (OSSL_FUNC)gofips_cipher128_freectx},
    {OSSL_FUNC_CIPHER_DUPCTX, (OSSL_FUNC)gofips_cipher128_dupctx},
    {OSSL_FUNC_CIPHER_ENCRYPT_INIT, (OSSL_FUNC)gofips_cipher_encrypt_init},
    {OSSL_FUNC_CIPHER_DECRYPT_INIT, (OSSL_FUNC)gofips_cipher_decrypt_init},
    {OSSL_FUNC_CIPHER_UPDATE, (OSSL_FUNC)gofips_cipher_update},
    {OSSL_FUNC_CIPHER_FINAL, (OSSL_FUNC)gofips_cipher_final},
    {OSSL_FUNC_CIPHER_CIPHER, (OSSL_FUNC)gofips_cipher_cipher},
    {OSSL_FUNC_CIPHER_GET_PARAMS, (OSSL_FUNC)gofips_cipher128_get_params},
    {OSSL_FUNC_CIPHER_GET_CTX_PARAMS, (OSSL_FUNC)gofips_cipher_get_ctx_params},
    {OSSL_FUNC_CIPHER_SET_CTX_PARAMS, (OSSL_FUNC)gofips_cipher_set_ctx_params},
    {OSSL_FUNC_CIPHER_GETTABLE_PARAMS, (OSSL_FUNC)gofips_cipher_gettable_params},
    {OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS, (OSSL_FUNC)gofips_cipher_gettable_ctx_params},
    {OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS, (OSSL_FUNC)gofips_cipher_settable_ctx_params},
    {0, NULL},
};

const OSSL_ALGORITHM gofips_cipher_algorithms[] = {
    /* AES-GCM carries fips=yes: it runs through the module's TLS 1.3 GCM
     * (NewGCMForTLS13), an approved IV-generation API in SP 2.7, which
     * conditions it on use "in the context of the respective protocols".
     * The label therefore covers TLS 1.3 record protection. A cipher row
     * cannot be limited to TLS callers; application-level GCM through
     * this row is outside the claim (README, audit page 03). AES-CBC
     * below stays without fips=yes. */
    {"AES-256-GCM:id-aes256-GCM:2.16.840.1.101.3.4.1.46", "provider=gofips,fips=yes", gofips_cipher_dispatch,
     "AES-256-GCM (Go Cryptographic Module v1.0.0, CMVP #5247; TLS 1.3 and TLS 1.2 GCM IV mechanisms, SP 2.7; for TLS record protection)"},
    {"AES-128-GCM:id-aes128-GCM:2.16.840.1.101.3.4.1.6", "provider=gofips,fips=yes", gofips_cipher128_dispatch,
     "AES-128-GCM (Go Cryptographic Module v1.0.0, CMVP #5247; TLS 1.3 and TLS 1.2 GCM IV mechanisms, SP 2.7; for TLS record protection)"},
    {"AES-256-CBC:AES256:2.16.840.1.101.3.4.1.42", "provider=gofips", gofips_cbc_dispatch,
     "AES-256-CBC (Go Cryptographic Module v1.0.0, CMVP #5247; PKCS#7; OpenSSL's TLS session tickets)"},
    {"AES-128-CBC:AES128:2.16.840.1.101.3.4.1.2", "provider=gofips", gofips_cbc128_dispatch,
     "AES-128-CBC (Go Cryptographic Module v1.0.0, CMVP #5247; PKCS#7; Node's TLS session tickets)"},
    {NULL, NULL, NULL, NULL},
};

/* EC keymgmt op */
extern void *gofips_keymgmt_new(int selection, void *provctx);
extern void gofips_keymgmt_free(void *keydata);
extern void *gofips_keymgmt_load(const unsigned char *reference, size_t reference_len, const char *structure, int selection, void *provctx);
extern int gofips_keymgmt_has(void *keydata, int selection);
extern int gofips_keymgmt_import(void *keydata, int selection, const OSSL_PARAM params[]);
extern int gofips_keymgmt_export(void *keydata, int selection, OSSL_CALLBACK *cb, void *cbarg);
extern const OSSL_PARAM *gofips_keymgmt_export_types(int selection);
extern const OSSL_PARAM *gofips_keymgmt_import_types(int selection);
extern int gofips_keymgmt_get_params(void *keydata, OSSL_PARAM params[]);
extern const OSSL_PARAM *gofips_keymgmt_gettable_params(void *keydata);
extern int gofips_keymgmt_set_params(void *keydata, const OSSL_PARAM params[]);
extern const OSSL_PARAM *gofips_keymgmt_settable_params(void *keydata);
extern int gofips_keymgmt_match(void *keydata1, void *keydata2, int selection);
extern int gofips_keymgmt_validate(void *keydata, int selection, int checktype);
extern const char *gofips_keymgmt_query_operation_name(int operation_id);
extern void *gofips_keymgmt_gen_init(void *provctx, int selection, const OSSL_PARAM params[]);
extern int gofips_keymgmt_gen_set_template(void *genctx, void *templ);
extern int gofips_keymgmt_gen_set_params(void *genctx, const OSSL_PARAM params[]);
extern const OSSL_PARAM *gofips_keymgmt_gen_settable_params(void *genctx, void *provctx);
extern int gofips_keymgmt_gen_get_params(void *genctx, OSSL_PARAM params[]);
extern const OSSL_PARAM *gofips_keymgmt_gen_gettable_params(void *genctx, void *provctx);
extern void *gofips_keymgmt_gen(void *genctx, OSSL_CALLBACK *cb, void *cbarg);
extern void gofips_keymgmt_gen_cleanup(void *genctx);
extern void *gofips_keymgmt_dup(void *keydata, int selection);

const OSSL_DISPATCH gofips_keymgmt_dispatch[] = {
    {OSSL_FUNC_KEYMGMT_NEW, (OSSL_FUNC)gofips_keymgmt_new},
    {OSSL_FUNC_KEYMGMT_FREE, (OSSL_FUNC)gofips_keymgmt_free},
    {OSSL_FUNC_KEYMGMT_LOAD, (OSSL_FUNC)gofips_keymgmt_load},
    {OSSL_FUNC_KEYMGMT_HAS, (OSSL_FUNC)gofips_keymgmt_has},
    {OSSL_FUNC_KEYMGMT_IMPORT, (OSSL_FUNC)gofips_keymgmt_import},
    {OSSL_FUNC_KEYMGMT_EXPORT, (OSSL_FUNC)gofips_keymgmt_export},
    {OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (OSSL_FUNC)gofips_keymgmt_export_types},
    {OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (OSSL_FUNC)gofips_keymgmt_import_types},
    {OSSL_FUNC_KEYMGMT_GET_PARAMS, (OSSL_FUNC)gofips_keymgmt_get_params},
    {OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (OSSL_FUNC)gofips_keymgmt_gettable_params},
    {OSSL_FUNC_KEYMGMT_SET_PARAMS, (OSSL_FUNC)gofips_keymgmt_set_params},
    {OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS, (OSSL_FUNC)gofips_keymgmt_settable_params},
    {OSSL_FUNC_KEYMGMT_MATCH, (OSSL_FUNC)gofips_keymgmt_match},
    {OSSL_FUNC_KEYMGMT_VALIDATE, (OSSL_FUNC)gofips_keymgmt_validate},
    {OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME, (OSSL_FUNC)gofips_keymgmt_query_operation_name},
    {OSSL_FUNC_KEYMGMT_GEN_INIT, (OSSL_FUNC)gofips_keymgmt_gen_init},
    {OSSL_FUNC_KEYMGMT_GEN_SET_TEMPLATE, (OSSL_FUNC)gofips_keymgmt_gen_set_template},
    {OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (OSSL_FUNC)gofips_keymgmt_gen_set_params},
    {OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS, (OSSL_FUNC)gofips_keymgmt_gen_settable_params},
    {OSSL_FUNC_KEYMGMT_GEN_GET_PARAMS, (OSSL_FUNC)gofips_keymgmt_gen_get_params},
    {OSSL_FUNC_KEYMGMT_GEN_GETTABLE_PARAMS, (OSSL_FUNC)gofips_keymgmt_gen_gettable_params},
    {OSSL_FUNC_KEYMGMT_GEN, (OSSL_FUNC)gofips_keymgmt_gen},
    {OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (OSSL_FUNC)gofips_keymgmt_gen_cleanup},
    {OSSL_FUNC_KEYMGMT_DUP, (OSSL_FUNC)gofips_keymgmt_dup},
    {0, NULL},
};

/* RSA public keys and RSA signature verification (rsa.go). No private
 * keys, key generation, signing or encryption. */
extern void *gofips_rsa_keymgmt_new(void *provctx);
extern void *gofips_rsa_pss_keymgmt_new(void *provctx);
extern void gofips_rsa_keymgmt_free(void *keydata);
extern int gofips_rsa_keymgmt_has(const void *keydata, int selection);
extern int gofips_rsa_keymgmt_import(void *keydata, int selection, const OSSL_PARAM params[]);
extern int gofips_rsa_keymgmt_export(void *keydata, int selection, OSSL_CALLBACK *cb, void *cbarg);
extern const OSSL_PARAM *gofips_rsa_keymgmt_key_types(int selection);
extern int gofips_rsa_keymgmt_get_params(void *keydata, OSSL_PARAM params[]);
extern const OSSL_PARAM *gofips_rsa_keymgmt_gettable_params(void *provctx);
extern int gofips_rsa_keymgmt_match(const void *keydata1, const void *keydata2, int selection);
extern int gofips_rsa_keymgmt_validate(const void *keydata, int selection, int checktype);
extern void *gofips_rsa_keymgmt_dup(const void *keydata, int selection);
extern const char *gofips_rsa_keymgmt_query_operation_name(int operation_id);

const OSSL_PARAM gofips_rsa_key_types[] = {
    {OSSL_PKEY_PARAM_RSA_N, OSSL_PARAM_UNSIGNED_INTEGER, NULL, 0, 0},
    {OSSL_PKEY_PARAM_RSA_E, OSSL_PARAM_UNSIGNED_INTEGER, NULL, 0, 0},
    {NULL, 0, NULL, 0, 0},
};

const OSSL_PARAM gofips_rsa_keymgmt_params[] = {
    {OSSL_PKEY_PARAM_BITS, OSSL_PARAM_INTEGER, NULL, 0, 0},
    {OSSL_PKEY_PARAM_SECURITY_BITS, OSSL_PARAM_INTEGER, NULL, 0, 0},
    {OSSL_PKEY_PARAM_MAX_SIZE, OSSL_PARAM_INTEGER, NULL, 0, 0},
    {OSSL_PKEY_PARAM_DEFAULT_DIGEST, OSSL_PARAM_UTF8_STRING, NULL, 0, 0},
    {OSSL_PKEY_PARAM_RSA_N, OSSL_PARAM_UNSIGNED_INTEGER, NULL, 0, 0},
    {OSSL_PKEY_PARAM_RSA_E, OSSL_PARAM_UNSIGNED_INTEGER, NULL, 0, 0},
    {NULL, 0, NULL, 0, 0},
};

int gofips_build_rsa_export_params(OSSL_PARAM out[], const unsigned char *n, size_t nlen,
                                   const unsigned char *e, size_t elen) {
    out[0] = (OSSL_PARAM){OSSL_PKEY_PARAM_RSA_N, OSSL_PARAM_UNSIGNED_INTEGER, (void *)n, nlen, 0};
    out[1] = (OSSL_PARAM){OSSL_PKEY_PARAM_RSA_E, OSSL_PARAM_UNSIGNED_INTEGER, (void *)e, elen, 0};
    out[2] = (OSSL_PARAM){NULL, 0, NULL, 0, 0};
    return 2;
}

const OSSL_DISPATCH gofips_rsa_keymgmt_dispatch[] = {
    {OSSL_FUNC_KEYMGMT_NEW, (OSSL_FUNC)gofips_rsa_keymgmt_new},
    {OSSL_FUNC_KEYMGMT_FREE, (OSSL_FUNC)gofips_rsa_keymgmt_free},
    {OSSL_FUNC_KEYMGMT_HAS, (OSSL_FUNC)gofips_rsa_keymgmt_has},
    {OSSL_FUNC_KEYMGMT_IMPORT, (OSSL_FUNC)gofips_rsa_keymgmt_import},
    {OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (OSSL_FUNC)gofips_rsa_keymgmt_key_types},
    {OSSL_FUNC_KEYMGMT_EXPORT, (OSSL_FUNC)gofips_rsa_keymgmt_export},
    {OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (OSSL_FUNC)gofips_rsa_keymgmt_key_types},
    {OSSL_FUNC_KEYMGMT_GET_PARAMS, (OSSL_FUNC)gofips_rsa_keymgmt_get_params},
    {OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (OSSL_FUNC)gofips_rsa_keymgmt_gettable_params},
    {OSSL_FUNC_KEYMGMT_MATCH, (OSSL_FUNC)gofips_rsa_keymgmt_match},
    {OSSL_FUNC_KEYMGMT_VALIDATE, (OSSL_FUNC)gofips_rsa_keymgmt_validate},
    {OSSL_FUNC_KEYMGMT_DUP, (OSSL_FUNC)gofips_rsa_keymgmt_dup},
    {OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME, (OSSL_FUNC)gofips_rsa_keymgmt_query_operation_name},
    {0, NULL},
};

/* RSA-PSS keys: the same operations, PSS verification only */
const OSSL_DISPATCH gofips_rsa_pss_keymgmt_dispatch[] = {
    {OSSL_FUNC_KEYMGMT_NEW, (OSSL_FUNC)gofips_rsa_pss_keymgmt_new},
    {OSSL_FUNC_KEYMGMT_FREE, (OSSL_FUNC)gofips_rsa_keymgmt_free},
    {OSSL_FUNC_KEYMGMT_HAS, (OSSL_FUNC)gofips_rsa_keymgmt_has},
    {OSSL_FUNC_KEYMGMT_IMPORT, (OSSL_FUNC)gofips_rsa_keymgmt_import},
    {OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (OSSL_FUNC)gofips_rsa_keymgmt_key_types},
    {OSSL_FUNC_KEYMGMT_EXPORT, (OSSL_FUNC)gofips_rsa_keymgmt_export},
    {OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (OSSL_FUNC)gofips_rsa_keymgmt_key_types},
    {OSSL_FUNC_KEYMGMT_GET_PARAMS, (OSSL_FUNC)gofips_rsa_keymgmt_get_params},
    {OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (OSSL_FUNC)gofips_rsa_keymgmt_gettable_params},
    {OSSL_FUNC_KEYMGMT_MATCH, (OSSL_FUNC)gofips_rsa_keymgmt_match},
    {OSSL_FUNC_KEYMGMT_VALIDATE, (OSSL_FUNC)gofips_rsa_keymgmt_validate},
    {OSSL_FUNC_KEYMGMT_DUP, (OSSL_FUNC)gofips_rsa_keymgmt_dup},
    {OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME, (OSSL_FUNC)gofips_rsa_keymgmt_query_operation_name},
    {0, NULL},
};

extern void *gofips_rsa_sig_newctx(void *provctx, const char *propq);
extern void gofips_rsa_sig_freectx(void *sctx);
extern void *gofips_rsa_sig_dupctx(void *sctx);
extern int gofips_rsa_sig_verify_init(void *sctx, void *provkey, const OSSL_PARAM params[]);
extern int gofips_rsa_sig_verify(void *sctx, const unsigned char *sig, size_t siglen, const unsigned char *tbs, size_t tbslen);
extern int gofips_rsa_sig_digest_verify_init(void *sctx, const char *mdname, void *provkey, const OSSL_PARAM params[]);
extern int gofips_rsa_sig_digest_verify(void *sctx, const unsigned char *sig, size_t siglen, const unsigned char *tbs, size_t tbslen);
extern int gofips_rsa_sig_digest_verify_update(void *sctx, const unsigned char *data, size_t datalen);
extern int gofips_rsa_sig_digest_verify_final(void *sctx, const unsigned char *sig, size_t siglen);
extern int gofips_rsa_sig_set_ctx_params(void *sctx, const OSSL_PARAM params[]);
extern int gofips_rsa_sig_get_ctx_params(void *sctx, OSSL_PARAM params[]);
extern const OSSL_PARAM *gofips_rsa_sig_settable_ctx_params(void *sctx, void *provctx);
extern const OSSL_PARAM *gofips_rsa_sig_gettable_ctx_params(void *sctx, void *provctx);

const OSSL_PARAM gofips_rsa_sig_settable_tbl[] = {
    {OSSL_SIGNATURE_PARAM_PAD_MODE, OSSL_PARAM_UTF8_STRING, NULL, 0, 0},
    {OSSL_SIGNATURE_PARAM_DIGEST, OSSL_PARAM_UTF8_STRING, NULL, 0, 0},
    {OSSL_SIGNATURE_PARAM_MGF1_DIGEST, OSSL_PARAM_UTF8_STRING, NULL, 0, 0},
    {OSSL_SIGNATURE_PARAM_PSS_SALTLEN, OSSL_PARAM_UTF8_STRING, NULL, 0, 0},
    {OSSL_SIGNATURE_PARAM_PROPERTIES, OSSL_PARAM_UTF8_STRING, NULL, 0, 0},
    {OSSL_SIGNATURE_PARAM_MGF1_PROPERTIES, OSSL_PARAM_UTF8_STRING, NULL, 0, 0},
    {OSSL_SIGNATURE_PARAM_TLS_VERSION, OSSL_PARAM_INTEGER, NULL, 0, 0},
    {NULL, 0, NULL, 0, 0},
};

const OSSL_PARAM gofips_rsa_sig_gettable_tbl[] = {
    {OSSL_SIGNATURE_PARAM_PAD_MODE, OSSL_PARAM_UTF8_STRING, NULL, 0, 0},
    {OSSL_SIGNATURE_PARAM_DIGEST, OSSL_PARAM_UTF8_STRING, NULL, 0, 0},
    {OSSL_SIGNATURE_PARAM_PSS_SALTLEN, OSSL_PARAM_INTEGER, NULL, 0, 0},
    {NULL, 0, NULL, 0, 0},
};

const OSSL_DISPATCH gofips_rsa_sig_dispatch[] = {
    {OSSL_FUNC_SIGNATURE_NEWCTX, (OSSL_FUNC)gofips_rsa_sig_newctx},
    {OSSL_FUNC_SIGNATURE_FREECTX, (OSSL_FUNC)gofips_rsa_sig_freectx},
    {OSSL_FUNC_SIGNATURE_DUPCTX, (OSSL_FUNC)gofips_rsa_sig_dupctx},
    {OSSL_FUNC_SIGNATURE_VERIFY_INIT, (OSSL_FUNC)gofips_rsa_sig_verify_init},
    {OSSL_FUNC_SIGNATURE_VERIFY, (OSSL_FUNC)gofips_rsa_sig_verify},
    {OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT, (OSSL_FUNC)gofips_rsa_sig_digest_verify_init},
    {OSSL_FUNC_SIGNATURE_DIGEST_VERIFY, (OSSL_FUNC)gofips_rsa_sig_digest_verify},
    {OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE, (OSSL_FUNC)gofips_rsa_sig_digest_verify_update},
    {OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL, (OSSL_FUNC)gofips_rsa_sig_digest_verify_final},
    {OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, (OSSL_FUNC)gofips_rsa_sig_set_ctx_params},
    {OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS, (OSSL_FUNC)gofips_rsa_sig_get_ctx_params},
    {OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS, (OSSL_FUNC)gofips_rsa_sig_settable_ctx_params},
    {OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS, (OSSL_FUNC)gofips_rsa_sig_gettable_ctx_params},
    {0, NULL},
};

/* HMAC keymgmt and signature (hmac_pkey.go): the TLS 1.3 PSK binder. */
extern void *gofips_hmac_keymgmt_new(void *provctx);
extern void gofips_hmac_keymgmt_free(void *keydata);
extern int gofips_hmac_keymgmt_has(const void *keydata, int selection);
extern int gofips_hmac_keymgmt_import(void *keydata, int selection, const OSSL_PARAM params[]);
extern int gofips_hmac_keymgmt_export(void *keydata, int selection, OSSL_CALLBACK *cb, void *cbarg);
extern const OSSL_PARAM *gofips_hmac_keymgmt_key_types(int selection);
extern int gofips_hmac_keymgmt_match(const void *keydata1, const void *keydata2, int selection);
extern void *gofips_hmac_keymgmt_dup(const void *keydata, int selection);
extern const char *gofips_hmac_keymgmt_query_operation_name(int operation_id);

const OSSL_PARAM gofips_hmac_key_types[] = {
    {OSSL_PKEY_PARAM_PRIV_KEY, OSSL_PARAM_OCTET_STRING, NULL, 0, 0},
    {OSSL_PKEY_PARAM_PROPERTIES, OSSL_PARAM_UTF8_STRING, NULL, 0, 0},
    {NULL, 0, NULL, 0, 0},
};

/* Built by hand: the provider links no libcrypto functions. */
int gofips_call_octet_cb(OSSL_CALLBACK *cb, void *cbarg, const char *key, const unsigned char *data, size_t len) {
    OSSL_PARAM p[2] = {{key, OSSL_PARAM_OCTET_STRING, (void *)data, len, OSSL_PARAM_UNMODIFIED}, {NULL, 0, NULL, 0, 0}};
    return cb(p, cbarg);
}

const OSSL_DISPATCH gofips_hmac_keymgmt_dispatch[] = {
    {OSSL_FUNC_KEYMGMT_NEW, (OSSL_FUNC)gofips_hmac_keymgmt_new},
    {OSSL_FUNC_KEYMGMT_FREE, (OSSL_FUNC)gofips_hmac_keymgmt_free},
    {OSSL_FUNC_KEYMGMT_HAS, (OSSL_FUNC)gofips_hmac_keymgmt_has},
    {OSSL_FUNC_KEYMGMT_IMPORT, (OSSL_FUNC)gofips_hmac_keymgmt_import},
    {OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (OSSL_FUNC)gofips_hmac_keymgmt_key_types},
    {OSSL_FUNC_KEYMGMT_EXPORT, (OSSL_FUNC)gofips_hmac_keymgmt_export},
    {OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (OSSL_FUNC)gofips_hmac_keymgmt_key_types},
    {OSSL_FUNC_KEYMGMT_MATCH, (OSSL_FUNC)gofips_hmac_keymgmt_match},
    {OSSL_FUNC_KEYMGMT_DUP, (OSSL_FUNC)gofips_hmac_keymgmt_dup},
    {OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME, (OSSL_FUNC)gofips_hmac_keymgmt_query_operation_name},
    {0, NULL},
};

extern void *gofips_hmac_sig_newctx(void *provctx, const char *propq);
extern void gofips_hmac_sig_freectx(void *sctx);
extern void *gofips_hmac_sig_dupctx(void *sctx);
extern int gofips_hmac_sig_digest_sign_init(void *sctx, const char *mdname, void *provkey, const OSSL_PARAM params[]);
extern int gofips_hmac_sig_digest_sign_update(void *sctx, const unsigned char *data, size_t datalen);
extern int gofips_hmac_sig_digest_sign_final(void *sctx, unsigned char *sig, size_t *siglen, size_t sigsize);

const OSSL_DISPATCH gofips_hmac_sig_dispatch[] = {
    {OSSL_FUNC_SIGNATURE_NEWCTX, (OSSL_FUNC)gofips_hmac_sig_newctx},
    {OSSL_FUNC_SIGNATURE_FREECTX, (OSSL_FUNC)gofips_hmac_sig_freectx},
    {OSSL_FUNC_SIGNATURE_DUPCTX, (OSSL_FUNC)gofips_hmac_sig_dupctx},
    {OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, (OSSL_FUNC)gofips_hmac_sig_digest_sign_init},
    {OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE, (OSSL_FUNC)gofips_hmac_sig_digest_sign_update},
    {OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL, (OSSL_FUNC)gofips_hmac_sig_digest_sign_final},
    {0, NULL},
};

const OSSL_ALGORITHM gofips_keymgmt_algorithms[] = {
    /* The name list must include the OID alias id-ecPublicKey
     * (the default provider's EC keymgmt registers "EC:id-ecPublicKey";
     * PROV_NAMES_EC). Under a concurrent first fetch, libcrypto's lazy
     * algorithm-store build can leave a thread mid-construction where
     * the 'EC' fetch fails; libcrypto then retries through the NID
     * alias 'id-ecPublicKey' (evp_pkey_ctx_new_from_name's
     * OBJ_sn2nid fallback), and the process-level fallback caches a
     * failure. With the alias present, both names resolve at any store
     * state. */
    {"EC:id-ecPublicKey:1.2.840.10045.2.1", "provider=gofips,fips=yes", gofips_keymgmt_dispatch,
     "EC P-256 and P-384 keymgmt (Go Cryptographic Module v1.0.0, CMVP #5247)"},
    {"RSA:rsaEncryption:1.2.840.113549.1.1.1", "provider=gofips,fips=yes", gofips_rsa_keymgmt_dispatch,
     "RSA public keys, for verification (Go Cryptographic Module v1.0.0, CMVP #5247)"},
    /* libssl enables the rsa_pss_rsae_* TLS 1.3 signature algorithms only
     * if an RSA-PSS key type can be fetched. Keys with RSA-PSS
     * restrictions are refused at import: they would not be enforced. */
    {"RSA-PSS:RSASSA-PSS:1.2.840.113549.1.1.10:rsassaPss", "provider=gofips,fips=yes", gofips_rsa_pss_keymgmt_dispatch,
     "RSA-PSS public keys without restrictions, for verification (Go Cryptographic Module v1.0.0, CMVP #5247)"},
    {"HMAC", "provider=gofips,fips=yes", gofips_hmac_keymgmt_dispatch,
     "HMAC keys, for HMAC signatures such as the TLS 1.3 PSK binder (Go Cryptographic Module v1.0.0, CMVP #5247)"},
    {NULL, NULL, NULL, NULL},
};

/* ECDH keyexch op */
extern void *gofips_keyexch_newctx(void *provctx);
extern int gofips_keyexch_init(void *kctx, void *provkey, const OSSL_PARAM params[]);
extern int gofips_keyexch_derive(void *kctx, unsigned char *secret, size_t *secretlen, size_t outlen);
extern int gofips_keyexch_set_peer(void *kctx, void *provkey);
extern void gofips_keyexch_freectx(void *kctx);
extern void *gofips_keyexch_dupctx(void *kctx);
extern int gofips_keyexch_set_ctx_params(void *kctx, const OSSL_PARAM params[]);
extern const OSSL_PARAM *gofips_keyexch_settable_ctx_params(void *kctx, void *provctx);
extern int gofips_keyexch_get_ctx_params(void *kctx, OSSL_PARAM params[]);
extern const OSSL_PARAM *gofips_keyexch_gettable_ctx_params(void *kctx, void *provctx);

const OSSL_DISPATCH gofips_keyexch_dispatch[] = {
    {OSSL_FUNC_KEYEXCH_NEWCTX, (OSSL_FUNC)gofips_keyexch_newctx},
    {OSSL_FUNC_KEYEXCH_INIT, (OSSL_FUNC)gofips_keyexch_init},
    {OSSL_FUNC_KEYEXCH_DERIVE, (OSSL_FUNC)gofips_keyexch_derive},
    {OSSL_FUNC_KEYEXCH_SET_PEER, (OSSL_FUNC)gofips_keyexch_set_peer},
    {OSSL_FUNC_KEYEXCH_FREECTX, (OSSL_FUNC)gofips_keyexch_freectx},
    {OSSL_FUNC_KEYEXCH_DUPCTX, (OSSL_FUNC)gofips_keyexch_dupctx},
    {OSSL_FUNC_KEYEXCH_SET_CTX_PARAMS, (OSSL_FUNC)gofips_keyexch_set_ctx_params},
    {OSSL_FUNC_KEYEXCH_SETTABLE_CTX_PARAMS, (OSSL_FUNC)gofips_keyexch_settable_ctx_params},
    {OSSL_FUNC_KEYEXCH_GET_CTX_PARAMS, (OSSL_FUNC)gofips_keyexch_get_ctx_params},
    {OSSL_FUNC_KEYEXCH_GETTABLE_CTX_PARAMS, (OSSL_FUNC)gofips_keyexch_gettable_ctx_params},
    {0, NULL},
};

const OSSL_ALGORITHM gofips_keyexch_algorithms[] = {
    {"ECDH", "provider=gofips,fips=yes", gofips_keyexch_dispatch,
     "ECDH P-256 and P-384 (Go Cryptographic Module v1.0.0, CMVP #5247)"},
    {NULL, NULL, NULL, NULL},
};

/* ECDSA signature op */
extern void *gofips_sig_newctx(void *provctx, const char *propq);
extern int gofips_sig_sign_init(void *sctx, void *provkey, const OSSL_PARAM params[]);
extern int gofips_sig_sign(void *sctx, unsigned char *sig, size_t *siglen, size_t sigsize, const unsigned char *tbs, size_t tbslen);
extern int gofips_sig_verify_init(void *sctx, void *provkey, const OSSL_PARAM params[]);
extern int gofips_sig_verify(void *sctx, const unsigned char *sig, size_t siglen, const unsigned char *tbs, size_t tbslen);
extern int gofips_sig_digest_sign_init(void *sctx, const char *mdname, void *provkey, const OSSL_PARAM params[]);
extern int gofips_sig_digest_sign(void *sctx, unsigned char *sigret, size_t *siglen, size_t sigsize, const unsigned char *tbs, size_t tbslen);
extern int gofips_sig_digest_verify_init(void *sctx, const char *mdname, void *provkey, const OSSL_PARAM params[]);
extern int gofips_sig_digest_verify(void *sctx, const unsigned char *sig, size_t siglen, const unsigned char *tbs, size_t tbslen);
extern int gofips_sig_digest_sign_update(void *sctx, const unsigned char *data, size_t datalen);
extern int gofips_sig_digest_sign_final(void *sctx, unsigned char *sig, size_t *siglen, size_t sigsize);
extern int gofips_sig_digest_verify_update(void *sctx, const unsigned char *data, size_t datalen);
extern int gofips_sig_digest_verify_final(void *sctx, const unsigned char *sig, size_t siglen);
extern void gofips_sig_freectx(void *sctx);
extern void *gofips_sig_dupctx(void *sctx);
extern int gofips_sig_get_ctx_params(void *sctx, OSSL_PARAM params[]);
extern int gofips_sig_set_ctx_params(void *sctx, const OSSL_PARAM params[]);
extern const OSSL_PARAM *gofips_sig_gettable_ctx_params(void *sctx, void *provctx);
extern const OSSL_PARAM *gofips_sig_settable_ctx_params(void *sctx, void *provctx);

const OSSL_DISPATCH gofips_sig_dispatch[] = {
    {OSSL_FUNC_SIGNATURE_NEWCTX, (OSSL_FUNC)gofips_sig_newctx},
    {OSSL_FUNC_SIGNATURE_SIGN_INIT, (OSSL_FUNC)gofips_sig_sign_init},
    {OSSL_FUNC_SIGNATURE_SIGN, (OSSL_FUNC)gofips_sig_sign},
    {OSSL_FUNC_SIGNATURE_VERIFY_INIT, (OSSL_FUNC)gofips_sig_verify_init},
    {OSSL_FUNC_SIGNATURE_VERIFY, (OSSL_FUNC)gofips_sig_verify},
    {OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, (OSSL_FUNC)gofips_sig_digest_sign_init},
    {OSSL_FUNC_SIGNATURE_DIGEST_SIGN, (OSSL_FUNC)gofips_sig_digest_sign},
    {OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE, (OSSL_FUNC)gofips_sig_digest_sign_update},
    {OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL, (OSSL_FUNC)gofips_sig_digest_sign_final},
    {OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT, (OSSL_FUNC)gofips_sig_digest_verify_init},
    {OSSL_FUNC_SIGNATURE_DIGEST_VERIFY, (OSSL_FUNC)gofips_sig_digest_verify},
    {OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE, (OSSL_FUNC)gofips_sig_digest_verify_update},
    {OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL, (OSSL_FUNC)gofips_sig_digest_verify_final},
    {OSSL_FUNC_SIGNATURE_FREECTX, (OSSL_FUNC)gofips_sig_freectx},
    {OSSL_FUNC_SIGNATURE_DUPCTX, (OSSL_FUNC)gofips_sig_dupctx},
    {OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS, (OSSL_FUNC)gofips_sig_get_ctx_params},
    {OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, (OSSL_FUNC)gofips_sig_set_ctx_params},
    {OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS, (OSSL_FUNC)gofips_sig_gettable_ctx_params},
    {OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS, (OSSL_FUNC)gofips_sig_settable_ctx_params},
    {0, NULL},
};

const OSSL_ALGORITHM gofips_sig_algorithms[] = {
    {"ECDSA", "provider=gofips,fips=yes", gofips_sig_dispatch,
     "ECDSA P-256 and P-384 (Go Cryptographic Module v1.0.0, CMVP #5247)"},
    {"RSA:rsaEncryption:1.2.840.113549.1.1.1", "provider=gofips,fips=yes", gofips_rsa_sig_dispatch,
     "RSA PKCS#1 v1.5 and PSS verification (Go Cryptographic Module v1.0.0, CMVP #5247)"},
    {"HMAC", "provider=gofips,fips=yes", gofips_hmac_sig_dispatch,
     "HMAC with SHA-2 or SHA-3, keys of 112 bits or more; TLS 1.3 PSK binder (Go Cryptographic Module v1.0.0, CMVP #5247)"},
    {NULL, NULL, NULL, NULL},
};

/* SHA-512 digest op (same ids as SHA-256 digest op) */
extern void *gofips_digest512_newctx(void *provctx);
extern void *gofips_digest512_dupctx(void *src);
extern int gofips_digest512_init(void *dctx, const OSSL_PARAM params[]);
extern int gofips_digest512_update(void *dctx, const unsigned char *in, size_t inl);
extern int gofips_digest512_final(void *dctx, unsigned char *out, size_t *outl, size_t outsz);
extern void gofips_digest512_freectx(void *dctx);
extern int gofips_digest512_get_params(OSSL_PARAM params[]);
extern int gofips_digest512_get_ctx_params(void *dctx, OSSL_PARAM params[]);
extern int gofips_digest512_set_ctx_params(void *dctx, const OSSL_PARAM params[]);
extern const OSSL_PARAM *gofips_digest512_gettable_ctx_params(void *dctx, const OSSL_PARAM params[]);
extern const OSSL_PARAM *gofips_digest512_settable_ctx_params(void *dctx, void *provctx);

const OSSL_DISPATCH gofips_digest512_dispatch[] = {
    {OSSL_FUNC_DIGEST_NEWCTX, (OSSL_FUNC)gofips_digest512_newctx},
    {OSSL_FUNC_DIGEST_INIT, (OSSL_FUNC)gofips_digest512_init},
    {OSSL_FUNC_DIGEST_UPDATE, (OSSL_FUNC)gofips_digest512_update},
    {OSSL_FUNC_DIGEST_FINAL, (OSSL_FUNC)gofips_digest512_final},
    {OSSL_FUNC_DIGEST_FREECTX, (OSSL_FUNC)gofips_digest512_freectx},
    {OSSL_FUNC_DIGEST_DUPCTX, (OSSL_FUNC)gofips_digest512_dupctx},
    {OSSL_FUNC_DIGEST_GET_PARAMS, (OSSL_FUNC)gofips_digest512_get_params},
    {OSSL_FUNC_DIGEST_GET_CTX_PARAMS, (OSSL_FUNC)gofips_digest512_get_ctx_params},
    {OSSL_FUNC_DIGEST_GETTABLE_CTX_PARAMS, (OSSL_FUNC)gofips_digest512_gettable_ctx_params},
    {OSSL_FUNC_DIGEST_SETTABLE_CTX_PARAMS, (OSSL_FUNC)gofips_digest512_settable_ctx_params},
    {0, NULL},
};

/* TLS13-KDF op, the KDF the TLS 1.3 key schedule fetches
 * (OSSL_KDF_NAME_TLS1_3_KDF in ssl/tls13_enc.c). */
extern void *gofips_tls13kdf_newctx(void *provctx);
extern void gofips_tls13kdf_freectx(void *kctx);
extern void gofips_tls13kdf_reset(void *kctx);
extern int gofips_tls13kdf_derive(void *kctx, unsigned char *key, size_t keylen, const OSSL_PARAM params[]);
extern int gofips_tls13kdf_set_ctx_params(void *kctx, const OSSL_PARAM params[]);
extern const OSSL_PARAM *gofips_tls13kdf_settable_ctx_params(void *kctx, void *provctx);
extern const OSSL_PARAM *gofips_tls13kdf_gettable_ctx_params(void *kctx, void *provctx);
extern int gofips_tls13kdf_get_ctx_params(void *kctx, OSSL_PARAM params[]);
extern const OSSL_PARAM *gofips_tls13kdf_gettable_params(void *provctx);
extern int gofips_tls13kdf_get_params(OSSL_PARAM params[]);
extern void *gofips_tls13kdf_dupctx(void *src);

const OSSL_DISPATCH gofips_tls13kdf_dispatch[] = {
    {OSSL_FUNC_KDF_NEWCTX, (OSSL_FUNC)gofips_tls13kdf_newctx},
    {OSSL_FUNC_KDF_DUPCTX, (OSSL_FUNC)gofips_tls13kdf_dupctx},
    {OSSL_FUNC_KDF_FREECTX, (OSSL_FUNC)gofips_tls13kdf_freectx},
    {OSSL_FUNC_KDF_RESET, (OSSL_FUNC)gofips_tls13kdf_reset},
    {OSSL_FUNC_KDF_DERIVE, (OSSL_FUNC)gofips_tls13kdf_derive},
    {OSSL_FUNC_KDF_GETTABLE_PARAMS, (OSSL_FUNC)gofips_tls13kdf_gettable_params},
    {OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS, (OSSL_FUNC)gofips_tls13kdf_gettable_ctx_params},
    {OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS, (OSSL_FUNC)gofips_tls13kdf_settable_ctx_params},
    {OSSL_FUNC_KDF_GET_PARAMS, (OSSL_FUNC)gofips_tls13kdf_get_params},
    {OSSL_FUNC_KDF_GET_CTX_PARAMS, (OSSL_FUNC)gofips_tls13kdf_get_ctx_params},
    {OSSL_FUNC_KDF_SET_CTX_PARAMS, (OSSL_FUNC)gofips_tls13kdf_set_ctx_params},
    {0, NULL},
};


