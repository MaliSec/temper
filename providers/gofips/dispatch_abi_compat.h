/*
 * dispatch_abi_compat.h, provider-ABI macros that exist in OpenSSL 3.5+
 * headers but not in OpenSSL 3.0.x (e.g. the ubuntu-24.04 CI runners,
 * OpenSSL 3.0.13). The gofips provider does not link against libcrypto:
 * the dispatch table is numeric function IDs and capability strings, and
 * those IDs are stable across the OpenSSL 3.x series. The added IDs here
 * are taken verbatim from OpenSSL 3.5.9 include/openssl/{core_dispatch,
 * core_names}.h and only fire when the building system's headers are
 * older, so a newer toolchain uses its own definitions unchanged.
 *
 * Compile check in CI: dispatch.c includes this header last, after the
 * system headers, so a 3.5+ host defines nothing here.
 */
#ifndef GOFIPS_DISPATCH_ABI_COMPAT_H
#define GOFIPS_DISPATCH_ABI_COMPAT_H

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>

/* OSSL_FUNC typedef: OpenSSL 3.5 introduced the concrete function-pointer
 * type; 3.0 headers use OSSL_FUNC_##name##_fn typedefs per function and
 * have no aggregate type. */
#ifndef OSSL_FUNC_TYPE_DEFINED
typedef void (*OSSL_FUNC)(void);
#endif

/* provider-level: OpenSSL 3.5 added RAND_BYTES at 1032 (3.0 stops at
 * GET_CAPABILITIES=1030 / GET_REASON_STRINGS=1029). */
#ifndef OSSL_FUNC_PROVIDER_RANDOM_BYTES
#define OSSL_FUNC_PROVIDER_RANDOM_BYTES 1032
#endif

/* keymgmt gen: OpenSSL 3.0 exposes keymgmt_gen_get_params only on the
 * keymgmt level (GEN_GET_PARAMS=15/GEN_GETTABLE_PARAMS=16 were added in
 * 3.5 for the genctx-level query). */
#ifndef OSSL_FUNC_KEYMGMT_GEN_GET_PARAMS
#define OSSL_FUNC_KEYMGMT_GEN_GET_PARAMS 15
#endif
#ifndef OSSL_FUNC_KEYMGMT_GEN_GETTABLE_PARAMS
#define OSSL_FUNC_KEYMGMT_GEN_GETTABLE_PARAMS 16
#endif

/* TLS-SIGALG capability param names: introduced in OpenSSL 3.2; 3.0.x
 * headers lack the whole block. Values verbatim from 3.5.9. */
#ifndef OSSL_CAPABILITY_TLS_SIGALG_CODE_POINT
#define OSSL_CAPABILITY_TLS_SIGALG_CODE_POINT "tls-sigalg-code-point"
#endif
#ifndef OSSL_CAPABILITY_TLS_SIGALG_HASH_NAME
#define OSSL_CAPABILITY_TLS_SIGALG_HASH_NAME "tls-sigalg-hash-name"
#endif
#ifndef OSSL_CAPABILITY_TLS_SIGALG_HASH_OID
#define OSSL_CAPABILITY_TLS_SIGALG_HASH_OID "tls-sigalg-hash-oid"
#endif
#ifndef OSSL_CAPABILITY_TLS_SIGALG_IANA_NAME
#define OSSL_CAPABILITY_TLS_SIGALG_IANA_NAME "tls-sigalg-iana-name"
#endif
#ifndef OSSL_CAPABILITY_TLS_SIGALG_KEYTYPE
#define OSSL_CAPABILITY_TLS_SIGALG_KEYTYPE "tls-sigalg-keytype"
#endif
#ifndef OSSL_CAPABILITY_TLS_SIGALG_KEYTYPE_OID
#define OSSL_CAPABILITY_TLS_SIGALG_KEYTYPE_OID "tls-sigalg-keytype-oid"
#endif
#ifndef OSSL_CAPABILITY_TLS_SIGALG_MAX_DTLS
#define OSSL_CAPABILITY_TLS_SIGALG_MAX_DTLS "tls-max-dtls"
#endif
#ifndef OSSL_CAPABILITY_TLS_SIGALG_MAX_TLS
#define OSSL_CAPABILITY_TLS_SIGALG_MAX_TLS "tls-max-tls"
#endif
#ifndef OSSL_CAPABILITY_TLS_SIGALG_MIN_DTLS
#define OSSL_CAPABILITY_TLS_SIGALG_MIN_DTLS "tls-min-dtls"
#endif
#ifndef OSSL_CAPABILITY_TLS_SIGALG_MIN_TLS
#define OSSL_CAPABILITY_TLS_SIGALG_MIN_TLS "tls-min-tls"
#endif
#ifndef OSSL_CAPABILITY_TLS_SIGALG_NAME
#define OSSL_CAPABILITY_TLS_SIGALG_NAME "tls-sigalg-name"
#endif
#ifndef OSSL_CAPABILITY_TLS_SIGALG_OID
#define OSSL_CAPABILITY_TLS_SIGALG_OID "tls-sigalg-oid"
#endif
#ifndef OSSL_CAPABILITY_TLS_SIGALG_SECURITY_BITS
#define OSSL_CAPABILITY_TLS_SIGALG_SECURITY_BITS "tls-sigalg-sec-bits"
#endif
#ifndef OSSL_CAPABILITY_TLS_SIGALG_SIG_NAME
#define OSSL_CAPABILITY_TLS_SIGALG_SIG_NAME "tls-sigalg-sig-name"
#endif
#ifndef OSSL_CAPABILITY_TLS_SIGALG_SIG_OID
#define OSSL_CAPABILITY_TLS_SIGALG_SIG_OID "tls-sigalg-sig-oid"
#endif

/* signature param newer libssl passes at verify init */
#ifndef OSSL_SIGNATURE_PARAM_TLS_VERSION
#define OSSL_SIGNATURE_PARAM_TLS_VERSION "tls-version"
#endif

#endif /* GOFIPS_DISPATCH_ABI_COMPAT_H */
