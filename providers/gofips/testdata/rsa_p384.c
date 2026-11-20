/* rsa_p384.c: RSA signature verification and P-384 through gofips, each
 * checked against the default provider, plus certificate chains and TLS 1.3
 * handshakes that need them.
 *
 *   rsa      keys of 2048/3072/4096 bits signed by the default provider
 *            (PKCS#1 v1.5 and PSS, SHA-256/384/512) verify in gofips;
 *            tampering, SHA-1, wrong salt lengths and every RSA private-key
 *            operation are refused.
 *   p384     key generation, ECDH and ECDSA interoperate with the default
 *            provider; P-521 and explicit curve parameters are refused.
 *   chains   X509_verify_cert in gofips over three-certificate chains that
 *            mix RSA, P-384 and P-256, with PKCS#1 and PSS signatures.
 *   tls      TLS 1.3 with gofips as the client against RSA and P-384
 *            servers, with certificate verification, and gofips as a
 *            P-384 server.
 *
 * Build:  cc -o rsa_p384 rsa_p384.c $(pkg-config --cflags --libs libssl libcrypto)
 * Run:    GODEBUG=fips140=on ./rsa_p384 <dir containing gofips.so>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/param_build.h>
#include <openssl/provider.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

static OSSL_LIB_CTX *D, *G;
static OSSL_PROVIDER *GP;
static int fails, checks, skipped;

#define CHECK(cond, ...) do { checks++; \
    if (cond) { printf("PASS: "); } else { printf("FAIL: "); fails++; } \
    printf(__VA_ARGS__); printf("\n"); ERR_clear_error(); } while (0)

static const unsigned char MSG[] = "certificate signature input, verified in the Go module";

static long gofips_ops(const char *name) {
    char *json = NULL, key[32];
    OSSL_PARAM p[2] = {OSSL_PARAM_construct_utf8_ptr("temperfips-ops", &json, 0), OSSL_PARAM_construct_end()};
    if (!OSSL_PROVIDER_get_params(GP, p) || json == NULL) return -1;
    snprintf(key, sizeof key, "\"%s\":", name);
    const char *c = strstr(json, key);
    return c ? atol(c + strlen(key)) : 0;
}

/* the public half of k as a key in library context L */
static EVP_PKEY *pub_in(OSSL_LIB_CTX *L, EVP_PKEY *k) {
    unsigned char *der = NULL;
    int n = i2d_PUBKEY(k, &der);
    const unsigned char *p = der;
    EVP_PKEY *r = n > 0 ? d2i_PUBKEY_ex(NULL, &p, n, L, NULL) : NULL;
    OPENSSL_free(der);
    return r;
}

static EVP_PKEY *priv_in(OSSL_LIB_CTX *L, EVP_PKEY *k) {
    unsigned char *der = NULL;
    int n = i2d_PrivateKey(k, &der);
    const unsigned char *p = der;
    EVP_PKEY *r = n > 0 ? d2i_AutoPrivateKey_ex(NULL, &p, n, L, NULL) : NULL;
    OPENSSL_free(der);
    return r;
}

static X509 *cert_in(OSSL_LIB_CTX *L, X509 *x) {
    unsigned char *der = NULL;
    int n = i2d_X509(x, &der);
    const unsigned char *p = der;
    X509 *r = X509_new_ex(L, NULL);
    if (n <= 0 || d2i_X509(&r, &p, n) == NULL) r = NULL;
    OPENSSL_free(der);
    return r;
}

/* pad: 0 none, RSA_PKCS1_PADDING or RSA_PKCS1_PSS_PADDING; salt used with PSS */
static void set_pad(EVP_PKEY_CTX *pc, int pad, int salt) {
    if (pad) EVP_PKEY_CTX_set_rsa_padding(pc, pad);
    if (pad == RSA_PKCS1_PSS_PADDING) EVP_PKEY_CTX_set_rsa_pss_saltlen(pc, salt);
}

static size_t sign(OSSL_LIB_CTX *L, EVP_PKEY *k, const char *md, int pad, int salt, unsigned char *sig) {
    EVP_MD_CTX *m = EVP_MD_CTX_new();
    EVP_PKEY_CTX *pc = NULL;
    size_t n = 1024;
    if (EVP_DigestSignInit_ex(m, &pc, md, L, NULL, k, NULL) != 1) n = 0;
    else {
        set_pad(pc, pad, salt);
        if (EVP_DigestSign(m, sig, &n, MSG, sizeof MSG) != 1) n = 0;
    }
    EVP_MD_CTX_free(m);
    return n;
}

/* streaming: Update in two parts, then Final; otherwise one-shot */
static int verify(OSSL_LIB_CTX *L, EVP_PKEY *k, const char *md, int pad, int salt, int streaming,
                  const unsigned char *msg, const unsigned char *sig, size_t n) {
    EVP_MD_CTX *m = EVP_MD_CTX_new();
    EVP_PKEY_CTX *pc = NULL;
    int ok = EVP_DigestVerifyInit_ex(m, &pc, md, L, NULL, k, NULL) == 1;
    if (ok) {
        set_pad(pc, pad, salt);
        if (streaming)
            ok = EVP_DigestVerifyUpdate(m, msg, 7) == 1 && EVP_DigestVerifyUpdate(m, msg + 7, sizeof MSG - 7) == 1
                 && EVP_DigestVerifyFinal(m, sig, n) == 1;
        else
            ok = EVP_DigestVerify(m, sig, n, msg, sizeof MSG) == 1;
    }
    EVP_MD_CTX_free(m);
    return ok;
}

static void case_rsa(void) {
    static const int sizes[] = {2048, 3072, 4096};
    static const char *mds[] = {"SHA2-256", "SHA2-384", "SHA2-512"};
    unsigned char sig[1024], bad[sizeof MSG];
    memcpy(bad, MSG, sizeof MSG);
    bad[5] ^= 1;
    long ops0 = gofips_ops("rsa");
    for (int s = 0; s < 3; s++) {
        EVP_PKEY *k = EVP_PKEY_Q_keygen(D, NULL, "RSA", (size_t)sizes[s]);
        EVP_PKEY *g = k ? pub_in(G, k) : NULL;
        CHECK(g != NULL, "rsa %d: public key imports into gofips", sizes[s]);
        if (!g) { EVP_PKEY_free(k); continue; }
        CHECK(EVP_PKEY_get_bits(g) == sizes[s] && EVP_PKEY_get_security_bits(g) == EVP_PKEY_get_security_bits(k)
              && EVP_PKEY_get_size(g) == EVP_PKEY_get_size(k),
              "rsa %d: bits %d, security bits %d, size %d match the default provider", sizes[s],
              EVP_PKEY_get_bits(g), EVP_PKEY_get_security_bits(g), EVP_PKEY_get_size(g));
        BIGNUM *n1 = NULL, *n2 = NULL;
        CHECK(EVP_PKEY_get_bn_param(g, OSSL_PKEY_PARAM_RSA_N, &n1) && EVP_PKEY_get_bn_param(k, OSSL_PKEY_PARAM_RSA_N, &n2)
              && BN_cmp(n1, n2) == 0, "rsa %d: modulus reads back unchanged", sizes[s]);
        BN_free(n1); BN_free(n2);
        for (int d = 0; d < 3; d++) {
            if (s > 0 && d > 0) continue;
            size_t n = sign(D, k, mds[d], RSA_PKCS1_PADDING, 0, sig);
            CHECK(n && verify(G, g, mds[d], RSA_PKCS1_PADDING, 0, 0, MSG, sig, n)
                  && verify(G, g, mds[d], RSA_PKCS1_PADDING, 0, 1, MSG, sig, n),
                  "rsa %d %s PKCS#1 v1.5: verifies one-shot and streaming", sizes[s], mds[d]);
            CHECK(n && !verify(G, g, mds[d], RSA_PKCS1_PADDING, 0, 0, bad, sig, n),
                  "rsa %d %s PKCS#1 v1.5: a changed message is rejected", sizes[s], mds[d]);
            n = sign(D, k, mds[d], RSA_PKCS1_PSS_PADDING, RSA_PSS_SALTLEN_DIGEST, sig);
            CHECK(n && verify(G, g, mds[d], RSA_PKCS1_PSS_PADDING, RSA_PSS_SALTLEN_DIGEST, 0, MSG, sig, n)
                  && verify(G, g, mds[d], RSA_PKCS1_PSS_PADDING, RSA_PSS_SALTLEN_AUTO, 1, MSG, sig, n),
                  "rsa %d %s PSS (salt = digest): verifies, also with salt length auto", sizes[s], mds[d]);
            CHECK(n && !verify(G, g, mds[d], RSA_PKCS1_PSS_PADDING, RSA_PSS_SALTLEN_DIGEST, 0, bad, sig, n),
                  "rsa %d %s PSS: a changed message is rejected", sizes[s], mds[d]);
        }
        if (s == 0) {
            /* FIPS 186-5 5.4: the salt is at most the hash length */
            size_t n = sign(D, k, "SHA2-256", RSA_PKCS1_PSS_PADDING, RSA_PSS_SALTLEN_MAX, sig);
            CHECK(n && verify(D, k, "SHA2-256", RSA_PKCS1_PSS_PADDING, RSA_PSS_SALTLEN_AUTO, 0, MSG, sig, n)
                  && !verify(G, g, "SHA2-256", RSA_PKCS1_PSS_PADDING, RSA_PSS_SALTLEN_AUTO, 0, MSG, sig, n)
                  && !verify(G, g, "SHA2-256", RSA_PKCS1_PSS_PADDING, RSA_PSS_SALTLEN_MAX, 0, MSG, sig, n),
                  "rsa PSS: a salt longer than the hash is refused (the default provider accepts it)");
            n = sign(D, k, "SHA2-256", RSA_PKCS1_PSS_PADDING, 20, sig);
            CHECK(n && verify(G, g, "SHA2-256", RSA_PKCS1_PSS_PADDING, 20, 0, MSG, sig, n)
                  && !verify(G, g, "SHA2-256", RSA_PKCS1_PSS_PADDING, 21, 0, MSG, sig, n)
                  && !verify(G, g, "SHA2-256", RSA_PKCS1_PSS_PADDING, RSA_PSS_SALTLEN_AUTO, 0, MSG, sig, n),
                  "rsa PSS (20-byte salt): verifies with salt 20; rejected with 21 and with auto (auto means digest length)");
            n = sign(D, k, "SHA2-256", RSA_PKCS1_PSS_PADDING, 33, sig);
            CHECK(n && !verify(G, g, "SHA2-256", RSA_PKCS1_PSS_PADDING, 33, 0, MSG, sig, n),
                  "rsa PSS: an explicit salt longer than the hash is refused");
            n = sign(D, k, "SHA1", RSA_PKCS1_PADDING, 0, sig);
            CHECK(n && !verify(G, g, "SHA1", RSA_PKCS1_PADDING, 0, 0, MSG, sig, n),
                  "rsa: a SHA-1 signature is refused");
            n = sign(D, k, "SHA2-256", RSA_PKCS1_PSS_PADDING, RSA_PSS_SALTLEN_DIGEST, sig);
            CHECK(n && !verify(G, g, "SHA2-256", RSA_PKCS1_PADDING, 0, 0, MSG, sig, n),
                  "rsa: a PSS signature is rejected as PKCS#1 v1.5");

            /* pre-hashed verify: EVP_PKEY_verify with the digest set on the ctx */
            unsigned char h[32];
            unsigned int hl = 0;
            EVP_Digest(MSG, sizeof MSG, h, &hl, EVP_sha256(), NULL);
            n = sign(D, k, "SHA2-256", RSA_PKCS1_PADDING, 0, sig);
            EVP_PKEY_CTX *pc = EVP_PKEY_CTX_new_from_pkey(G, g, NULL);
            EVP_MD *gmd = EVP_MD_fetch(G, "SHA2-256", NULL);
            CHECK(pc && EVP_PKEY_verify_init(pc) == 1 && EVP_PKEY_CTX_set_signature_md(pc, gmd) == 1
                  && EVP_PKEY_verify(pc, sig, n, h, hl) == 1, "rsa: EVP_PKEY_verify over a SHA-256 digest");
            EVP_MD_free(gmd);
            EVP_PKEY_CTX_free(pc);

            /* an RSA-PSS key verifies PSS only */
            EVP_PKEY *pk = NULL;
            EVP_PKEY_CTX *pkc = EVP_PKEY_CTX_new_from_name(D, "RSA-PSS", NULL); /* 3.0's Q_keygen has no RSA-PSS */
            if (pkc && EVP_PKEY_keygen_init(pkc) == 1 && EVP_PKEY_CTX_set_rsa_keygen_bits(pkc, 2048) == 1)
                EVP_PKEY_keygen(pkc, &pk);
            EVP_PKEY_CTX_free(pkc);
            EVP_PKEY *gpk = pk ? pub_in(G, pk) : NULL;
            size_t m1 = gpk ? sign(D, pk, "SHA2-256", RSA_PKCS1_PSS_PADDING, RSA_PSS_SALTLEN_DIGEST, sig) : 0;
            int pss_ok = m1 && verify(G, gpk, "SHA2-256", RSA_PKCS1_PSS_PADDING, RSA_PSS_SALTLEN_DIGEST, 0, MSG, sig, m1);
            size_t m2 = sign(D, k, "SHA2-256", RSA_PKCS1_PADDING, 0, sig);
            EVP_PKEY *as_pss = NULL;
            if (gpk) {
                /* the PKCS#1 signature made by k, checked with k's modulus loaded as an RSA-PSS key */
                BIGNUM *bn = NULL, *be = NULL;
                EVP_PKEY_get_bn_param(g, OSSL_PKEY_PARAM_RSA_N, &bn);
                EVP_PKEY_get_bn_param(g, OSSL_PKEY_PARAM_RSA_E, &be);
                OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
                OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, bn);
                OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, be);
                OSSL_PARAM *bp = OSSL_PARAM_BLD_to_param(bld);
                EVP_PKEY_CTX *fc = EVP_PKEY_CTX_new_from_name(G, "RSA-PSS", NULL);
                if (fc && EVP_PKEY_fromdata_init(fc) == 1) EVP_PKEY_fromdata(fc, &as_pss, EVP_PKEY_PUBLIC_KEY, bp);
                EVP_PKEY_CTX_free(fc);
                OSSL_PARAM_free(bp);
                OSSL_PARAM_BLD_free(bld);
                BN_free(bn); BN_free(be);
            }
            CHECK(pss_ok && as_pss && verify(G, g, "SHA2-256", RSA_PKCS1_PADDING, 0, 0, MSG, sig, m2)
                  && !verify(G, as_pss, "SHA2-256", RSA_PKCS1_PADDING, 0, 0, MSG, sig, m2),
                  "rsa: an RSA-PSS key verifies PSS and refuses PKCS#1 v1.5");
            EVP_PKEY_free(as_pss);
            EVP_PKEY_free(gpk);
            EVP_PKEY_free(pk);

            pc = EVP_PKEY_CTX_new_from_pkey(G, g, NULL);
            CHECK(pc && EVP_PKEY_sign_init(pc) != 1, "rsa: signing is refused (no RSA private-key operations)");
            EVP_PKEY_CTX_free(pc);
            pc = EVP_PKEY_CTX_new_from_pkey(G, g, NULL);
            CHECK(pc && EVP_PKEY_encrypt_init(pc) != 1, "rsa: encryption is refused");
            EVP_PKEY_CTX_free(pc);
            /* libcrypto keeps a refused private key as a legacy key; no
             * operation on it may succeed */
            EVP_PKEY *gp = priv_in(G, k);
            CHECK(gp == NULL || sign(G, gp, "SHA2-256", RSA_PKCS1_PADDING, 0, sig) == 0,
                  "rsa: a private key cannot sign (%s)", gp ? "kept as a legacy key" : "not imported");
            EVP_PKEY_free(gp);
            gp = EVP_PKEY_Q_keygen(G, NULL, "RSA", (size_t)2048);
            CHECK(gp == NULL, "rsa: key generation is refused");
            EVP_PKEY_free(gp);
        }
        EVP_PKEY_free(g);
        EVP_PKEY_free(k);
    }
    /* keys the module marks non-approved: FIPS 186-5 5.1 and 5.5(e) */
    static const struct { int bits; unsigned long e; const char *what; } weak[] = {
        {1024, 65537, "a 1024-bit modulus"}, {2047, 65537, "an odd-length modulus"},
        {2048, 3, "e = 3"}, {2048, 65537, "a 2048-bit modulus with e = 65537 (control)"},
    };
    for (int i = 0; i < 4; i++) {
        EVP_PKEY_CTX *kc = EVP_PKEY_CTX_new_from_name(D, "RSA", NULL);
        EVP_PKEY *k = NULL;
        BIGNUM *e = BN_new();
        BN_set_word(e, weak[i].e);
        if (kc && EVP_PKEY_keygen_init(kc) == 1 && EVP_PKEY_CTX_set_rsa_keygen_bits(kc, weak[i].bits) == 1
            && EVP_PKEY_CTX_set1_rsa_keygen_pubexp(kc, e) == 1)
            EVP_PKEY_keygen(kc, &k);
        BN_free(e);
        EVP_PKEY_CTX_free(kc);
        EVP_PKEY *g = k ? pub_in(G, k) : NULL;
        size_t n = k ? sign(D, k, "SHA2-256", RSA_PKCS1_PADDING, 0, sig) : 0;
        int ok = g && n && verify(G, g, "SHA2-256", RSA_PKCS1_PADDING, 0, 0, MSG, sig, n);
        int approved = weak[i].bits >= 2048 && weak[i].bits % 2 == 0 && weak[i].e > 65536;
        CHECK(k && ok == approved, "rsa: %s is %s", weak[i].what, approved ? "accepted" : "refused (non-approved in the module)");
        EVP_PKEY_free(g);
        EVP_PKEY_free(k);
    }
    long ops = gofips_ops("rsa") - ops0;
    CHECK(ops > 0, "rsa: verifications executed in the Go module (%ld counted)", ops);
}

static int ecdh(EVP_PKEY *priv, EVP_PKEY *peer, OSSL_LIB_CTX *L, unsigned char *out, size_t *n) {
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_pkey(L, priv, NULL);
    *n = 128;
    int ok = c && EVP_PKEY_derive_init(c) == 1 && EVP_PKEY_derive_set_peer(c, peer) == 1 && EVP_PKEY_derive(c, out, n) == 1;
    EVP_PKEY_CTX_free(c);
    return ok;
}

static void case_p384(void) {
    unsigned char sig[256], s1[128], s2[128];
    char group[32] = "";
    size_t n, l1, l2;
    EVP_PKEY *g = EVP_PKEY_Q_keygen(G, NULL, "EC", "P-384");
    EVP_PKEY *d = EVP_PKEY_Q_keygen(D, NULL, "EC", "P-384");
    CHECK(g && d, "p384: key generation in gofips");
    if (!g || !d) return;
    EVP_PKEY_get_utf8_string_param(g, OSSL_PKEY_PARAM_GROUP_NAME, group, sizeof group, NULL);
    CHECK(strcmp(group, "secp384r1") == 0 && EVP_PKEY_get_bits(g) == 384 && EVP_PKEY_get_security_bits(g) == 192
          && EVP_PKEY_get_size(g) == EVP_PKEY_get_size(d),
          "p384: group %s, 384 bits, 192 security bits, size %d (default %d)", group, EVP_PKEY_get_size(g), EVP_PKEY_get_size(d));
    EVP_PKEY *gpub_d = pub_in(D, g), *dpub_g = pub_in(G, d);
    CHECK(gpub_d && dpub_g && ecdh(g, dpub_g, G, s1, &l1) && ecdh(d, gpub_d, D, s2, &l2) && l1 == 48 && l1 == l2
          && memcmp(s1, s2, l1) == 0, "p384: ECDH secret from gofips equals the default provider's (48 bytes)");
    static const char *mds[] = {"SHA2-256", "SHA2-384", "SHA2-512"};
    for (int i = 0; i < 3; i++) {
        n = sign(G, g, mds[i], 0, 0, sig);
        CHECK(n && verify(D, gpub_d, mds[i], 0, 0, 0, MSG, sig, n), "p384 %s: a gofips signature verifies in the default provider", mds[i]);
        n = sign(D, d, mds[i], 0, 0, sig);
        CHECK(n && verify(G, dpub_g, mds[i], 0, 0, 0, MSG, sig, n) && verify(G, dpub_g, mds[i], 0, 0, 1, MSG, sig, n),
              "p384 %s: a default-provider signature verifies in gofips, one-shot and streaming", mds[i]);
    }
    EVP_PKEY *dpriv_g = priv_in(G, d);
    n = dpriv_g ? sign(G, dpriv_g, "SHA2-384", 0, 0, sig) : 0;
    CHECK(n && verify(D, d, "SHA2-384", 0, 0, 0, MSG, sig, n), "p384: a private key imported from the default provider signs in gofips");
    EVP_PKEY_free(dpriv_g);

    /* pre-hashed ECDSA has no digest to check the input against: refused */
    EVP_PKEY_CTX *ph = EVP_PKEY_CTX_new_from_pkey(G, g, NULL);
    unsigned char dg[48] = {1};
    n = sizeof sig;
    CHECK(ph && EVP_PKEY_sign_init(ph) == 1 && EVP_PKEY_sign(ph, sig, &n, dg, 48) != 1,
          "p384: pre-hashed EVP_PKEY_sign is refused (no digest set)");
    EVP_PKEY_CTX_free(ph);
    EVP_PKEY *g256 = EVP_PKEY_Q_keygen(G, NULL, "EC", "P-256");
    CHECK(g256 && EVP_PKEY_parameters_eq(g, g256) != 1 && EVP_PKEY_eq(g, g256) != 1,
          "p384: a P-384 and a P-256 key do not match");
    EVP_PKEY_free(g256);
    EVP_PKEY_CTX *ng = EVP_PKEY_CTX_new_from_name(G, "EC", NULL);
    EVP_PKEY *nk = NULL;
    CHECK(ng && EVP_PKEY_keygen_init(ng) == 1 && EVP_PKEY_keygen(ng, &nk) != 1,
          "ec: key generation with no group set is refused");
    EVP_PKEY_free(nk);
    EVP_PKEY_CTX_free(ng);

    EVP_PKEY *p521 = EVP_PKEY_Q_keygen(G, NULL, "EC", "P-521");
    CHECK(p521 == NULL, "p521: key generation is refused");
    EVP_PKEY_free(p521);
    EVP_PKEY *d521 = EVP_PKEY_Q_keygen(D, NULL, "EC", "P-521"), *g521 = pub_in(G, d521);
    CHECK(g521 == NULL, "p521: a public key does not import");
    EVP_PKEY_free(g521);
    EVP_PKEY_free(d521);
    /* import with the point plus: nothing (control), the decoder's
     * decoded-from-explicit flag, or an explicit curve parameter */
    unsigned char pt[97];
    size_t ptlen = 0;
    EVP_PKEY_get_octet_string_param(d, OSSL_PKEY_PARAM_PUB_KEY, pt, sizeof pt, &ptlen);
    for (int i = 0; i < 3; i++) {
        int flag = i == 1;
        OSSL_PARAM ip[] = {
            OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, "secp384r1", 0),
            OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, pt, ptlen),
            i == 1 ? OSSL_PARAM_construct_int(OSSL_PKEY_PARAM_EC_DECODED_FROM_EXPLICIT_PARAMS, &flag)
                   : OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_EC_FIELD_TYPE, "prime-field", 0),
            OSSL_PARAM_construct_end(),
        };
        if (i == 0) ip[2] = OSSL_PARAM_construct_end();
        EVP_PKEY *fx = NULL;
        EVP_PKEY_CTX *fc = EVP_PKEY_CTX_new_from_name(G, "EC", NULL);
        int ok = fc && EVP_PKEY_fromdata_init(fc) == 1 && EVP_PKEY_fromdata(fc, &fx, EVP_PKEY_PUBLIC_KEY, ip) == 1;
        static const char *what[] = {"a named-curve point imports (control)",
                                     "a key decoded from explicit parameters is refused at import",
                                     "explicit curve parameters are refused at import"};
        CHECK(ok == (i == 0), "p384: %s", what[i]);
        EVP_PKEY_free(fx);
        EVP_PKEY_CTX_free(fc);
    }
    EVP_PKEY_free(gpub_d);
    EVP_PKEY_free(dpub_g);
    EVP_PKEY_free(g);
    EVP_PKEY_free(d);
}

static void add_ext(X509 *x, X509V3_CTX *v, int nid, const char *value) {
    X509_EXTENSION *e = X509V3_EXT_nconf_nid(NULL, v, nid, value);
    if (e) X509_add_ext(x, e, -1);
    X509_EXTENSION_free(e);
}

/* a certificate made with the default provider; issuer NULL for a root */
static X509 *mkcert(EVP_PKEY *key, const char *cn, X509 *issuer, EVP_PKEY *ikey, const char *md, int ca, int pss) {
    static long serial = 1;
    X509 *x = X509_new_ex(D, NULL);
    X509_set_version(x, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(x), serial++);
    X509_gmtime_adj(X509_getm_notBefore(x), -3600);
    X509_gmtime_adj(X509_getm_notAfter(x), 86400);
    X509_set_pubkey(x, key);
    X509_NAME *nm = X509_NAME_new();
    X509_NAME_add_entry_by_txt(nm, "CN", MBSTRING_ASC, (const unsigned char *)cn, -1, -1, 0);
    X509_set_subject_name(x, nm);
    X509_set_issuer_name(x, issuer ? X509_get_subject_name(issuer) : nm);
    X509_NAME_free(nm);
    X509V3_CTX v;
    X509V3_set_ctx(&v, issuer ? issuer : x, x, NULL, NULL, 0);
    add_ext(x, &v, NID_basic_constraints, ca ? "critical,CA:TRUE" : "critical,CA:FALSE");
    add_ext(x, &v, NID_key_usage, ca ? "critical,keyCertSign,cRLSign" : "critical,digitalSignature");
    add_ext(x, &v, NID_subject_key_identifier, "hash");
    if (issuer) add_ext(x, &v, NID_authority_key_identifier, "keyid:always");
    if (!ca) {
        add_ext(x, &v, NID_ext_key_usage, "serverAuth");
        add_ext(x, &v, NID_subject_alt_name, "DNS:gofips.test");
    }
    EVP_MD_CTX *m = EVP_MD_CTX_new();
    EVP_PKEY_CTX *pc = NULL;
    int ok = EVP_DigestSignInit_ex(m, &pc, md, D, NULL, ikey ? ikey : key, NULL) == 1;
    if (ok && pss) set_pad(pc, RSA_PKCS1_PSS_PADDING, RSA_PSS_SALTLEN_DIGEST);
    if (!ok || X509_sign_ctx(x, m) <= 0) { X509_free(x); x = NULL; }
    EVP_MD_CTX_free(m);
    return x;
}

/* X509_verify_cert in gofips: leaf <- mid <- root (root trusted) */
static int verify_chain(X509 *root, X509 *mid, X509 *leaf, int *err) {
    X509 *r = cert_in(G, root), *m = cert_in(G, mid), *l = cert_in(G, leaf);
    X509_STORE *st = X509_STORE_new();
    STACK_OF(X509) *u = sk_X509_new_null();
    X509_STORE_CTX *c = X509_STORE_CTX_new_ex(G, NULL);
    X509_STORE_add_cert(st, r);
    sk_X509_push(u, m);
    int ok = X509_STORE_CTX_init(c, st, l, u) == 1 && X509_verify_cert(c) == 1;
    *err = X509_STORE_CTX_get_error(c);
    X509_STORE_CTX_free(c);
    sk_X509_free(u);
    X509_STORE_free(st);
    X509_free(r); X509_free(m); X509_free(l);
    return ok;
}

static EVP_PKEY *rsa_root, *p384_root, *rsa_mid, *p384_mid, *p256_leaf, *rsa_leaf;
static X509 *c_rsa_root, *c_p384_mid, *c_p256_leaf, *c_p384_root, *c_rsa_mid, *c_rsa_leaf;

static void case_chains(void) {
    int err;
    rsa_root = EVP_PKEY_Q_keygen(D, NULL, "RSA", (size_t)3072);
    p384_root = EVP_PKEY_Q_keygen(D, NULL, "EC", "P-384");
    rsa_mid = EVP_PKEY_Q_keygen(D, NULL, "RSA", (size_t)2048);
    p384_mid = EVP_PKEY_Q_keygen(D, NULL, "EC", "P-384");
    p256_leaf = EVP_PKEY_Q_keygen(D, NULL, "EC", "P-256");
    rsa_leaf = EVP_PKEY_Q_keygen(D, NULL, "RSA", (size_t)2048);

    c_rsa_root = mkcert(rsa_root, "RSA root", NULL, NULL, "SHA2-256", 1, 0);
    /* Under GODEBUG=fips140=only Go refuses SHA-1, so libcrypto cannot
     * compute certificate fingerprints. OpenSSL 3.0.13 then builds no chain
     * (X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY); 3.5.7 and 4.0.3 do. */
    X509 *probe = cert_in(G, c_rsa_root);
    int nofp = probe && (X509_get_extension_flags(probe) & EXFLAG_NO_FINGERPRINT);
    X509_free(probe);
    if (nofp && OpenSSL_version_num() < 0x30500000L) {
        printf("SKIP: chains and TLS: no SHA-1 certificate fingerprints, and OpenSSL %s builds no chain without them\n",
               OpenSSL_version(OPENSSL_VERSION_STRING));
        skipped = 1;
        return;
    }
    c_p384_mid = mkcert(p384_mid, "P-384 intermediate", c_rsa_root, rsa_root, "SHA2-384", 1, 0);
    c_p256_leaf = mkcert(p256_leaf, "gofips.test", c_p384_mid, p384_mid, "SHA2-384", 0, 0);
    CHECK(c_rsa_root && c_p384_mid && c_p256_leaf && verify_chain(c_rsa_root, c_p384_mid, c_p256_leaf, &err),
          "chain RSA-3072 root -> P-384 intermediate -> P-256 leaf (PKCS#1 v1.5, ECDSA-SHA384) verifies (%d)", err);

    c_p384_root = mkcert(p384_root, "P-384 root", NULL, NULL, "SHA2-384", 1, 0);
    c_rsa_mid = mkcert(rsa_mid, "RSA intermediate", c_p384_root, p384_root, "SHA2-384", 1, 0);
    c_rsa_leaf = mkcert(rsa_leaf, "gofips.test", c_rsa_mid, rsa_mid, "SHA2-256", 0, 1);
    CHECK(c_p384_root && c_rsa_mid && c_rsa_leaf && verify_chain(c_p384_root, c_rsa_mid, c_rsa_leaf, &err),
          "chain P-384 root -> RSA-2048 intermediate -> RSA-2048 leaf (ECDSA-SHA384, RSA-PSS) verifies (%d)", err);

    X509 *sha1_mid = mkcert(p384_mid, "P-384 intermediate", c_rsa_root, rsa_root, "SHA1", 1, 0);
    CHECK(sha1_mid && !verify_chain(c_rsa_root, sha1_mid, c_p256_leaf, &err),
          "chain with a SHA-1-signed intermediate is rejected (%d: %s)", err, X509_verify_cert_error_string(err));
    X509_free(sha1_mid);

    /* an intermediate whose key is encoded with explicit curve parameters
     * fails the chain: gofips refuses the key, so it cannot be an issuer
     * (the default provider reports X509_V_ERR_EC_KEY_EXPLICIT_PARAMS) */
    EVP_PKEY *xk = EVP_PKEY_Q_keygen(D, NULL, "EC", "P-384");
    EVP_PKEY_set_utf8_string_param(xk, OSSL_PKEY_PARAM_EC_ENCODING, OSSL_PKEY_EC_ENCODING_EXPLICIT);
    X509 *xmid = mkcert(xk, "explicit intermediate", c_rsa_root, rsa_root, "SHA2-384", 1, 0);
    X509 *xleaf = mkcert(p256_leaf, "gofips.test", xmid, xk, "SHA2-384", 0, 0);
    CHECK(xmid && xleaf && !verify_chain(c_rsa_root, xmid, xleaf, &err),
          "chain with an explicit-parameter intermediate key is rejected (%d: %s)", err, X509_verify_cert_error_string(err));
    X509_free(xleaf);
    X509_free(xmid);
    EVP_PKEY_free(xk);

    EVP_PKEY *other = EVP_PKEY_Q_keygen(D, NULL, "RSA", (size_t)2048);
    X509 *other_root = mkcert(other, "RSA root", NULL, NULL, "SHA2-256", 1, 0);
    CHECK(other_root && !verify_chain(other_root, c_p384_mid, c_p256_leaf, &err),
          "chain under a different key with the same root name is rejected (%d: %s)", err, X509_verify_cert_error_string(err));
    X509_free(other_root);
    EVP_PKEY_free(other);
}

static int pump(SSL *cl, SSL *sv) {
    for (int i = 0; i < 200; i++) {
        int a = SSL_is_init_finished(cl) ? 1 : SSL_do_handshake(cl);
        int b = SSL_is_init_finished(sv) ? 1 : SSL_do_handshake(sv);
        if (a == 1 && b == 1) return 1;
        int ea = a == 1 ? SSL_ERROR_NONE : SSL_get_error(cl, a);
        int eb = b == 1 ? SSL_ERROR_NONE : SSL_get_error(sv, b);
        if ((ea != SSL_ERROR_NONE && ea != SSL_ERROR_WANT_READ && ea != SSL_ERROR_WANT_WRITE) ||
            (eb != SSL_ERROR_NONE && eb != SSL_ERROR_WANT_READ && eb != SSL_ERROR_WANT_WRITE)) return 0;
    }
    return 0;
}

/* client in CL verifying against root; server in SV with leaf, mid and key */
static void tls_case(const char *label, OSSL_LIB_CTX *CL, OSSL_LIB_CTX *SV, const char *groups,
                     X509 *root, X509 *mid, X509 *leaf, EVP_PKEY *key, int want_group) {
    SSL_CTX *cc = SSL_CTX_new_ex(CL, NULL, TLS_client_method()), *sc = SSL_CTX_new_ex(SV, NULL, TLS_server_method());
    X509 *r = cert_in(CL, root), *m = cert_in(SV, mid), *l = cert_in(SV, leaf);
    EVP_PKEY *k = priv_in(SV, key);
    int ok = cc && sc && r && m && l && k;
    if (ok) {
        SSL_CTX_set_min_proto_version(cc, TLS1_3_VERSION);
        SSL_CTX_set_min_proto_version(sc, TLS1_3_VERSION);
        SSL_CTX_set_options(sc, SSL_OP_NO_TICKET);
        SSL_CTX_set_num_tickets(sc, 0);
        ok = (!groups || (SSL_CTX_set1_groups_list(cc, groups) && SSL_CTX_set1_groups_list(sc, groups)))
             && X509_STORE_add_cert(SSL_CTX_get_cert_store(cc), r) == 1
             && SSL_CTX_use_certificate(sc, l) == 1 && SSL_CTX_add1_chain_cert(sc, m) == 1
             && SSL_CTX_use_PrivateKey(sc, k) == 1;
        SSL_CTX_set_verify(cc, SSL_VERIFY_PEER, NULL);
    }
    if (!ok) {
        CHECK(0, "tls %s: context setup", label);
        ERR_print_errors_fp(stdout);
    } else {
        SSL *cl = SSL_new(cc), *sv = SSL_new(sc);
        BIO *c2s_w, *c2s_r, *s2c_w, *s2c_r;
        BIO_new_bio_pair(&c2s_w, 1 << 16, &c2s_r, 1 << 16);
        BIO_new_bio_pair(&s2c_w, 1 << 16, &s2c_r, 1 << 16);
        SSL_set_bio(cl, s2c_r, c2s_w);
        SSL_set_bio(sv, c2s_r, s2c_w);
        SSL_set_connect_state(cl);
        SSL_set_accept_state(sv);
        X509_VERIFY_PARAM_set1_host(SSL_get0_param(cl), "gofips.test", 0);
        int hs = pump(cl, sv);
        int grp = hs ? SSL_get_negotiated_group(cl) : 0;
        int signid = 0;
        const char *sigalg = hs && SSL_get_peer_signature_type_nid(cl, &signid) ? OBJ_nid2sn(signid) : NULL;
        CHECK(hs && SSL_get_verify_result(cl) == X509_V_OK && (!want_group || grp == want_group),
              "tls %s: handshake completes, server chain verified (group %s, peer signature type %s)", label,
              OBJ_nid2sn(grp & 0xffff), sigalg ? sigalg : "?");
        if (!hs) ERR_print_errors_fp(stdout);
        SSL_free(cl);
        SSL_free(sv);
    }
    SSL_CTX_free(cc); SSL_CTX_free(sc);
    X509_free(r); X509_free(m); X509_free(l); EVP_PKEY_free(k);
}

static void case_tls(void) {
    if (skipped) return;
    long r0 = gofips_ops("rsa"), e0 = gofips_ops("ecdsa"), x0 = gofips_ops("ecdh");
    tls_case("gofips client -> default server, RSA-2048 leaf (RSA-PSS)", G, D, NULL,
             c_p384_root, c_rsa_mid, c_rsa_leaf, rsa_leaf, 0);
    tls_case("gofips client -> default server, P-256 leaf under RSA root, group P-384", G, D, "P-384",
             c_rsa_root, c_p384_mid, c_p256_leaf, p256_leaf, NID_secp384r1);
    tls_case("default client -> gofips server, group P-384", D, G, "P-384",
             c_rsa_root, c_p384_mid, c_p256_leaf, p256_leaf, NID_secp384r1);
    EVP_PKEY *k384 = EVP_PKEY_Q_keygen(D, NULL, "EC", "P-384");
    X509 *leaf384 = mkcert(k384, "gofips.test", c_p384_mid, p384_mid, "SHA2-384", 0, 0);
    tls_case("default client -> gofips server, P-384 leaf (gofips signs with P-384)", D, G, NULL,
             c_rsa_root, c_p384_mid, leaf384, k384, 0);
    tls_case("gofips client -> gofips server, P-384 leaf", G, G, NULL, c_rsa_root, c_p384_mid, leaf384, k384, 0);
    X509_free(leaf384);
    EVP_PKEY_free(k384);
    printf("  tls: gofips operations: rsa %ld, ecdsa %ld, ecdh %ld\n", gofips_ops("rsa") - r0,
           gofips_ops("ecdsa") - e0, gofips_ops("ecdh") - x0);
    CHECK(gofips_ops("rsa") > r0 && gofips_ops("ecdh") > x0, "tls: RSA verification and ECDH ran in the Go module");
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <dir containing gofips.so>\n", argv[0]); return 2; }
    D = OSSL_LIB_CTX_new();
    G = OSSL_LIB_CTX_new();
    if (!OSSL_PROVIDER_load(D, "default")) { printf("default provider failed to load\n"); return 2; }
    OSSL_PROVIDER_set_default_search_path(G, argv[1]);
    GP = OSSL_PROVIDER_load(G, "gofips");
    if (!GP || !OSSL_PROVIDER_load(G, "base")) { printf("gofips/base provider failed to load\n"); return 2; }
    case_rsa();
    case_p384();
    case_chains();
    case_tls();
    if (fails) printf("RSAP384: %d FAILURES (%d checks)\n", fails, checks);
    else if (skipped) printf("RSAP384: ALL PASS (%d checks, chains and TLS skipped)\n", checks);
    else printf("RSAP384: ALL PASS (%d checks)\n", checks);
    return fails ? 1 : 0;
}
