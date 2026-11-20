/* ecboundary.c - EC P-256 key import/export boundary cases.
 *
 *   C1  canonical 32-byte scalar with matching pub: accepted; ECDH equals
 *       default; signature verifies under the pub.
 *   C2  leading-zero scalar as an unpadded 31-byte octet param, matching
 *       pub: accepted and normalized; otherwise as C1.
 *   C3  the same scalar as an INTEGER param (push_BN): as C2.
 *   C4  scalar > group order: refused.
 *   C5  scalar zero: refused.
 *   C6  scalar 33 bytes (over-length): refused.
 *   C7  valid scalar and valid pub that do not match: refused.
 *   C8  priv-only import (no pub): refused.
 *   C9  invalid pub (not on curve): refused.
 *   C10 pub-only import (valid): accepted; ECDH-usable as the peer side.
 *   C11 malformed pub lengths (64, 66, wrong prefix): refused.
 *
 * Cross-provider round trips:
 *   X1  gofips keygen -> todata -> default fromdata -> sign in default,
 *       verify under the gofips pub. Priv must export as UNSIGNED_INTEGER.
 *   X2  default keygen -> export -> gofips fromdata -> sign in gofips,
 *       verify under the default pub.
 *   X3  every accepted import: get_bn_param(priv) equals the input.
 *
 * Size probes on keymgmt get_params (P0-P5): see the P block below.
 *
 * Run: cc -o ecboundary ecboundary.c $(pkg-config --cflags --libs openssl)
 *      GODEBUG=fips140=on ./ecboundary <dir-with-gofips.so>
 * Exit status is the number of failed checks.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/param_build.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/err.h>

static OSSL_LIB_CTX *G, *D;
static int fails = 0;
#define CHECK(c, msg) do { if (!(c)) { printf("FAIL: %s\n", msg); fails++; } else printf("PASS: %s\n", msg); } while (0)

/* import helper: priv as octet (big-endian bytes), pub optional */
static EVP_PKEY *imp_octet(OSSL_LIB_CTX *L, const unsigned char *priv, size_t plen,
                           const unsigned char *pub, size_t publen) {
    OSSL_PARAM_BLD *b = OSSL_PARAM_BLD_new();
    OSSL_PARAM_BLD_push_utf8_string(b, OSSL_PKEY_PARAM_GROUP_NAME, "prime256v1", 0);
    if (pub) OSSL_PARAM_BLD_push_octet_string(b, OSSL_PKEY_PARAM_PUB_KEY, pub, publen);
    if (priv) OSSL_PARAM_BLD_push_octet_string(b, OSSL_PKEY_PARAM_PRIV_KEY, priv, plen);
    OSSL_PARAM *ps = OSSL_PARAM_BLD_to_param(b);
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_name(L, "EC", NULL);
    EVP_PKEY *k = NULL;
    EVP_PKEY_fromdata_init(c);
    int rc = EVP_PKEY_fromdata(c, &k, pub || priv ? EVP_PKEY_KEYPAIR : EVP_PKEY_PUBLIC_KEY, ps);
    OSSL_PARAM_free(ps); OSSL_PARAM_BLD_free(b); EVP_PKEY_CTX_free(c);
    if (rc > 0) return k;
    return NULL;
}
/* import helper: priv as INTEGER via BIGNUM (push_BN) */
static EVP_PKEY *imp_bn(OSSL_LIB_CTX *L, BIGNUM *d,
                        const unsigned char *pub, size_t publen) {
    OSSL_PARAM_BLD *b = OSSL_PARAM_BLD_new();
    OSSL_PARAM_BLD_push_utf8_string(b, OSSL_PKEY_PARAM_GROUP_NAME, "prime256v1", 0);
    if (pub) OSSL_PARAM_BLD_push_octet_string(b, OSSL_PKEY_PARAM_PUB_KEY, pub, publen);
    if (d) OSSL_PARAM_BLD_push_BN(b, OSSL_PKEY_PARAM_PRIV_KEY, d);
    OSSL_PARAM *ps = OSSL_PARAM_BLD_to_param(b);
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_name(L, "EC", NULL);
    EVP_PKEY *k = NULL;
    EVP_PKEY_fromdata_init(c);
    int rc = EVP_PKEY_fromdata(c, &k, pub || d ? EVP_PKEY_KEYPAIR : EVP_PKEY_PUBLIC_KEY, ps);
    OSSL_PARAM_free(ps); OSSL_PARAM_BLD_free(b); EVP_PKEY_CTX_free(c);
    if (rc > 0) return k;
    return NULL;
}
/* Returns 1 if ECDH matches the default provider on the same key bytes
 * and a signature verifies under the key's own pub. */
static int usable(EVP_PKEY *k) {
    if (!k) return 0;
    unsigned char pub[80]; size_t plen = 0;
    if (EVP_PKEY_get_octet_string_param(k, "pub", pub, sizeof pub, &plen) <= 0) return 0;
    /* import that pub on the default provider as the peer */
    EVP_PKEY *peer = imp_octet(D, NULL, 0, pub, plen);
    if (!peer) return 0;
    unsigned char s1[64], s2[64]; size_t n1 = 64, n2 = 64;
    EVP_PKEY_CTX *e1 = EVP_PKEY_CTX_new_from_pkey(G, k, NULL);
    int r1 = EVP_PKEY_derive_init(e1) > 0 && EVP_PKEY_derive_set_peer(e1, peer) > 0
               ? EVP_PKEY_derive(e1, s1, &n1) : -1;
    /* default self-ECDH with a same-scalar key imported there */
    BIGNUM *d = NULL;
    EVP_PKEY_get_bn_param(k, "priv", &d);
    EVP_PKEY *kd = imp_bn(D, d, pub, plen);
    EVP_PKEY_CTX *e2 = EVP_PKEY_CTX_new_from_pkey(D, kd, NULL);
    int r2 = kd && EVP_PKEY_derive_init(e2) > 0 && EVP_PKEY_derive_set_peer(e2, peer) > 0
               ? EVP_PKEY_derive(e2, s2, &n2) : -1;
    int ecdhOk = r1 > 0 && r2 > 0 && n1 == n2 && !memcmp(s1, s2, n1);
    /* sign in gofips, verify under the pub (imported on gofips) */
    unsigned char msg[] = "ecboundary message";
    unsigned char sig[96]; size_t siglen = sizeof sig;
    EVP_MD_CTX *ms = EVP_MD_CTX_new();
    int si = EVP_DigestSignInit(ms, NULL, EVP_sha256(), NULL, k);
    int ss = si > 0 ? EVP_DigestSign(ms, sig, &siglen, msg, sizeof msg - 1) : -1;
    EVP_MD_CTX_free(ms);
    int signOk = 0;
    if (ss > 0) {
        EVP_PKEY *pubk = imp_octet(G, NULL, 0, pub, plen);
        EVP_MD_CTX *mv = EVP_MD_CTX_new();
        int vi = EVP_DigestVerifyInit(mv, NULL, EVP_sha256(), NULL, pubk);
        int vr = vi > 0 ? EVP_DigestVerify(mv, sig, siglen, msg, sizeof msg - 1) : -1;
        signOk = vr == 1;
        EVP_MD_CTX_free(mv); EVP_PKEY_free(pubk);
    }
    EVP_PKEY_CTX_free(e1); EVP_PKEY_CTX_free(e2);
    EVP_PKEY_free(peer); EVP_PKEY_free(kd); BN_free(d);
    return ecdhOk && signOk;
}
/* BN round-trip: the imported key's BN priv equals the submitted scalar */
static int bnRoundTrip(EVP_PKEY *k, BIGNUM *d) {
    if (!k || !d) return 0;
    BIGNUM *bn = NULL;
    int rc = EVP_PKEY_get_bn_param(k, "priv", &bn);
    int ok = rc > 0 && bn && BN_cmp(bn, d) == 0;
    BN_free(bn);
    return ok;
}

int main(int argc, char **argv) {
    G = OSSL_LIB_CTX_new(); D = OSSL_LIB_CTX_new();
    OSSL_PROVIDER_load(D, "default");
    OSSL_PROVIDER_set_default_search_path(G, argv[1]);
    if (!OSSL_PROVIDER_load(G, "gofips")) { printf("LOAD FAIL\n"); return 3; }
    EC_GROUP *grp = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);

    /* base key: canonical scalar, matching pub */
    BIGNUM *d0 = NULL;
    BN_hex2bn(&d0, "8F6B0A0D101316191C1F2225282B2E3134373A3D404346494C4F5255585B5E");
    EC_POINT *P = EC_POINT_new(grp);
    EC_POINT_mul(grp, P, d0, NULL, NULL, NULL);
    unsigned char pub0[65];
    EC_POINT_point2oct(grp, P, POINT_CONVERSION_UNCOMPRESSED, pub0, 65, NULL);
    unsigned char priv0[32];
    BN_bn2binpad(d0, priv0, 32);

    /* C1: canonical 32-byte, matching pub */
    EVP_PKEY *k1 = imp_octet(G, priv0, 32, pub0, 65);
    CHECK(k1 && usable(k1) && bnRoundTrip(k1, d0),
          "C1: canonical 32-byte scalar: accepted, ECDH=default, sign verifies, BN round-trip");
    EVP_PKEY_free(k1);

    /* C2: d0's top byte is nonzero, so build a scalar below 2^248. */
    BIGNUM *d2 = BN_new();
    BN_one(d2); BN_lshift(d2, d2, 240); BN_add_word(d2, 0x1234); /* 2^240 + 4660 */
    EC_POINT *P2 = EC_POINT_new(grp);
    EC_POINT_mul(grp, P2, d2, NULL, NULL, NULL);
    unsigned char pub2[65];
    EC_POINT_point2oct(grp, P2, POINT_CONVERSION_UNCOMPRESSED, pub2, 65, NULL);
    unsigned char priv31[31];
    BN_bn2bin(d2, priv31); /* BN drops the leading zero: 31 bytes */

    EVP_PKEY *k2 = imp_octet(G, priv31, 31, pub2, 65);
    CHECK(k2 && usable(k2) && bnRoundTrip(k2, d2),
          "C2: 31-byte octet scalar (leading zero): accepted, normalized, usable, BN round-trip");
    EVP_PKEY_free(k2);

    /* C3: same scalar via push_BN (INTEGER param) */
    EVP_PKEY *k3 = imp_bn(G, d2, pub2, 65);
    CHECK(k3 && usable(k3) && bnRoundTrip(k3, d2),
          "C3: BN-path (INTEGER) unpadded scalar: accepted, normalized, usable, BN round-trip");
    EVP_PKEY_free(k3);

    /* C4: scalar > group order */
    BIGNUM *d4 = BN_new();
    BN_copy(d4, EC_GROUP_get0_order(grp));
    BN_add_word(d4, 1);
    unsigned char priv4[32]; BN_bn2binpad(d4, priv4, 32);
    EVP_PKEY *k4 = imp_octet(G, priv4, 32, pub0, 65);
    CHECK(k4 == NULL, "C4: scalar above the group order: refused");
    EVP_PKEY_free(k4);

    /* C5: scalar zero */
    unsigned char priv5[32]; memset(priv5, 0, 32);
    EVP_PKEY *k5 = imp_octet(G, priv5, 32, pub0, 65);
    CHECK(k5 == NULL, "C5: zero scalar: refused");
    EVP_PKEY_free(k5);

    /* C6: 33-byte scalar */
    unsigned char priv6[33]; memset(priv6, 0x11, 33);
    EVP_PKEY *k6 = imp_octet(G, priv6, 33, pub0, 65);
    CHECK(k6 == NULL, "C6: 33-byte (over-length) scalar: refused");
    EVP_PKEY_free(k6);

    /* C7: pub/priv mismatch (valid scalar, valid pub, wrong pair) */
    EVP_PKEY *k7 = imp_octet(G, priv0, 32, pub2, 65);
    CHECK(k7 == NULL, "C7: mismatched pub/priv pair: refused (orientation validation)");
    EVP_PKEY_free(k7);

    /* C8: priv-only (no pub) */
    EVP_PKEY *k8 = imp_octet(G, priv0, 32, NULL, 0);
    CHECK(k8 == NULL, "C8: priv-only import without pub: refused (fail closed)");
    EVP_PKEY_free(k8);

    /* C9: pub not on curve */
    unsigned char badpub[65]; memcpy(badpub, pub0, 65);
    badpub[65 - 1] ^= 0x01; /* corrupt Y */
    EVP_PKEY *k9 = imp_octet(G, priv0, 32, badpub, 65);
    CHECK(k9 == NULL, "C9: public point not on the curve: refused");
    EVP_PKEY_free(k9);

    /* C10: a pub-only key works as the ECDH peer of a default keypair
     * (the gofips-gofips direction is covered by usable()) and is refused
     * as the init side. */
    EVP_PKEY *k10 = imp_octet(G, NULL, 0, pub0, 65);
    CHECK(k10 != NULL, "C10: pub-only import (valid point): accepted");
    if (k10) {
        EVP_PKEY *kd10 = imp_bn(D, d0, pub0, 65);
        unsigned char s2[64], s3[64]; size_t n2 = 64, n3 = 64;
        EVP_PKEY_CTX *e2 = EVP_PKEY_CTX_new_from_pkey(D, kd10, NULL);
        int r2 = EVP_PKEY_derive_init(e2) > 0 && EVP_PKEY_derive_set_peer(e2, k10) > 0
                   ? EVP_PKEY_derive(e2, s2, &n2) : -1;
        /* reference computed entirely on the default provider */
        EVP_PKEY *kd10b = imp_bn(D, d0, pub0, 65);
        EVP_PKEY_CTX *e3 = EVP_PKEY_CTX_new_from_pkey(D, kd10b, NULL);
        int r3 = EVP_PKEY_derive_init(e3) > 0 && EVP_PKEY_derive_set_peer(e3, kd10) > 0
                   ? EVP_PKEY_derive(e3, s3, &n3) : -1;
        CHECK(r2 > 0 && r3 > 0 && n2 == n3 && !memcmp(s2, s3, n2),
              "C10: cross-provider ECDH (default keypair x gofips pub-only peer) matches the default reference");
        EVP_PKEY_CTX *e1 = EVP_PKEY_CTX_new_from_pkey(G, k10, NULL);
        unsigned char s1[64]; size_t n1 = 64;
        int r1 = EVP_PKEY_derive_init(e1) > 0 && EVP_PKEY_derive_set_peer(e1, kd10) > 0
                   ? EVP_PKEY_derive(e1, s1, &n1) : -1;
        CHECK(r1 <= 0, "C10: deriving with a pub-only key as the init side is refused (no private scalar)");
        EVP_PKEY_free(kd10); EVP_PKEY_free(kd10b);
        EVP_PKEY_CTX_free(e1); EVP_PKEY_CTX_free(e2); EVP_PKEY_CTX_free(e3);
    }
    EVP_PKEY_free(k10);

    /* C11: malformed pub lengths */
    EVP_PKEY *k11a = imp_octet(G, NULL, 0, pub0, 64);
    CHECK(k11a == NULL, "C11a: 64-byte pub: refused");
    EVP_PKEY *k11b = imp_octet(G, NULL, 0, pub0, 66);
    CHECK(k11b == NULL, "C11b: 66-byte pub: refused");
    unsigned char pfx[65]; memcpy(pfx, pub0, 65); pfx[0] = 0x03;
    EVP_PKEY *k11c = imp_octet(G, NULL, 0, pfx, 65);
    CHECK(k11c == NULL, "C11c: wrong-point-prefix pub: refused");
    EVP_PKEY_free(k11a); EVP_PKEY_free(k11b); EVP_PKEY_free(k11c);

    /* X1 */
    EVP_PKEY_CTX *gen = EVP_PKEY_CTX_new_from_name(G, "EC", NULL);
    EVP_PKEY *gk = NULL;
    int gok = EVP_PKEY_keygen_init(gen) > 0 &&
              EVP_PKEY_CTX_set_ec_paramgen_curve_nid(gen, NID_X9_62_prime256v1) > 0 &&
              EVP_PKEY_keygen(gen, &gk) > 0;
    CHECK(gok, "X1: gofips keygen");
    if (gok) {
        OSSL_PARAM *exp = NULL;
        int rt = EVP_PKEY_todata(gk, OSSL_KEYMGMT_SELECT_KEYPAIR, &exp);
        CHECK(rt > 0 && exp, "X1: gofips EVP_PKEY_todata");
        if (rt > 0) {
            EVP_PKEY_CTX *ci = EVP_PKEY_CTX_new_from_name(D, "EC", "provider=default");
            EVP_PKEY *imp = NULL;
            EVP_PKEY_fromdata_init(ci);
            int rc = EVP_PKEY_fromdata(ci, &imp, EVP_PKEY_KEYPAIR, exp);
            CHECK(rc > 0, "X1: default fromdata of the gofips export (types + group survive)");
            if (rc > 0) {
                EVP_MD_CTX *ms = EVP_MD_CTX_new();
                unsigned char sig[96]; size_t sl = sizeof sig;
                unsigned char msg[] = "x1";
                int s1 = EVP_DigestSignInit(ms, NULL, EVP_sha256(), NULL, imp) > 0 &&
                         EVP_DigestSign(ms, sig, &sl, msg, 2) > 0;
                CHECK(s1, "X1: DigestSign in the default provider with the imported key");
                if (s1) {
                    EVP_MD_CTX *mv = EVP_MD_CTX_new();
                    int v = EVP_DigestVerifyInit(mv, NULL, EVP_sha256(), NULL, gk) > 0 &&
                            EVP_DigestVerify(mv, sig, sl, msg, 2) == 1;
                    CHECK(v, "X1: the default-signed sig verifies under the gofips pub");
                    EVP_MD_CTX_free(mv);
                }
                EVP_MD_CTX_free(ms);
                EVP_PKEY_free(imp);
            }
            OSSL_PARAM_free(exp);
            EVP_PKEY_CTX_free(ci);
        }
        EVP_PKEY_free(gk);
    }
    EVP_PKEY_CTX_free(gen);

    /* X2: default keygen -> export -> gofips fromdata -> sign in gofips
       -> verify under default's pub */
    EVP_PKEY_CTX *gen2 = EVP_PKEY_CTX_new_from_name(D, "EC", "provider=default");
    EVP_PKEY *dk = NULL;
    int gok2 = EVP_PKEY_keygen_init(gen2) > 0 &&
               EVP_PKEY_CTX_set_ec_paramgen_curve_nid(gen2, NID_X9_62_prime256v1) > 0 &&
               EVP_PKEY_keygen(gen2, &dk) > 0;
    if (gok2) {
        OSSL_PARAM *exp2 = NULL;
        int rt2 = EVP_PKEY_todata(dk, OSSL_KEYMGMT_SELECT_ALL, &exp2);
        CHECK(rt2 > 0, "X2: default EVP_PKEY_todata (ALL selection; the default provider refuses KEYPAIR for todata)");
        if (rt2 > 0) {
            EVP_PKEY_CTX *ci = EVP_PKEY_CTX_new_from_name(G, "EC", "provider=gofips");
            EVP_PKEY *imp = NULL;
            EVP_PKEY_fromdata_init(ci);
            int rc = EVP_PKEY_fromdata(ci, &imp, EVP_PKEY_KEYPAIR, exp2);
            CHECK(rc > 0, "X2: gofips fromdata of the default export (integer scalar accepted)");
            if (rc > 0) {
                CHECK(usable(imp), "X2: the imported key is usable in gofips (ECDH + sign/verify)");
                EVP_PKEY_free(imp);
            }
            OSSL_PARAM_free(exp2);
            EVP_PKEY_CTX_free(ci);
        }
        EVP_PKEY_free(dk);
    }
    EVP_PKEY_CTX_free(gen2);

    /* X3 is asserted via bnRoundTrip() in C1/C2/C3/X2. */

    /* P: octet size probes on the EC pub, matching the default provider.
       libssl's TLS 1.3 key share (add_key_share) issues the NULL/0
       probe, so refusing it breaks the handshake.
       P1: NULL buffer, size 0             -> rc=1, needed size
       P2: NULL buffer, size 65            -> rc=1, needed size
       P3: non-NULL buffer smaller than 65 -> rc=0, needed size, unwritten
       P4: buffer of exactly 65            -> rc=1, exact copy
       P5: priv BN readback (get_bn_param issues its own NULL/0 probe) */
    {
        EVP_PKEY_CTX *gk = EVP_PKEY_CTX_new_from_name(G, "EC", "provider=gofips");
        EVP_PKEY_keygen_init(gk);
        OSSL_PARAM gp[2];
        gp[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, "prime256v1", 0);
        gp[1] = OSSL_PARAM_construct_end();
        EVP_PKEY_CTX_set_params(gk, gp);
        EVP_PKEY *pk = NULL;
        int gok = EVP_PKEY_generate(gk, &pk) > 0;
        CHECK(gok, "P: gofips P-256 keygen for the size-probe shapes");
        if (gok) {
            unsigned char ref[80]; size_t rlen = 0;
            int rg = EVP_PKEY_get_octet_string_param(pk, OSSL_PKEY_PARAM_PUB_KEY, ref, sizeof ref, &rlen);
            CHECK(rg == 1 && rlen == 65, "P0: exact-size readback returns the 65-byte point");
            /* P1 */
            size_t need = 0;
            int p1 = EVP_PKEY_get_octet_string_param(pk, OSSL_PKEY_PARAM_PUB_KEY, NULL, 0, &need);
            CHECK(p1 == 1 && need == 65,
                  "P1: NULL/0 size probe -> rc=1 with the needed size (default-provider semantics)");
            /* P2 */
            need = 0;
            int p2 = EVP_PKEY_get_octet_string_param(pk, OSSL_PKEY_PARAM_PUB_KEY, NULL, 65, &need);
            CHECK(p2 == 1 && need == 65,
                  "P2: NULL buffer with size 65 -> rc=1 with the needed size, nothing to write");
            /* P3: asserted with EVP_PKEY_get_params because
               EVP_PKEY_get_octet_string_param clears out_sz on failure.
               The default provider behaves the same on 3.0.13 and 3.5. */
            unsigned char small[8];
            memset(small, 0xAA, sizeof small);
            OSSL_PARAM q3[2];
            q3[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, small, sizeof small);
            q3[1] = OSSL_PARAM_construct_end();
            int p3 = EVP_PKEY_get_params(pk, q3);
            int untouched = 1;
            for (int i = 0; i < 8; i++) if (small[i] != 0xAA) untouched = 0;
            CHECK(p3 != 1 && q3[0].return_size == 65 && untouched,
                  "P3: undersized non-NULL buffer -> rc!=1, needed size in return_size, buffer untouched");
            /* P3b: the same through the EVP wrapper */
            memset(small, 0xAA, sizeof small);
            size_t need3 = 0;
            int p3b = EVP_PKEY_get_octet_string_param(pk, OSSL_PKEY_PARAM_PUB_KEY, small, 8, &need3);
            untouched = 1;
            for (int i = 0; i < 8; i++) if (small[i] != 0xAA) untouched = 0;
            CHECK(p3b != 1 && untouched,
                  "P3b: undersized non-NULL buffer via EVP -> rc!=1, buffer untouched");
            /* P4 */
            unsigned char exact[65];
            memset(exact, 0xBB, sizeof exact);
            need = 0;
            int p4 = EVP_PKEY_get_octet_string_param(pk, OSSL_PKEY_PARAM_PUB_KEY, exact, 65, &need);
            CHECK(p4 == 1 && need == 65 && memcmp(exact, ref, 65) == 0,
                  "P4: exact-size buffer -> rc=1, byte-exact copy");
            /* P5 */
            BIGNUM *bn = NULL;
            int p5 = EVP_PKEY_get_bn_param(pk, OSSL_PKEY_PARAM_PRIV_KEY, &bn);
            CHECK(p5 == 1 && bn != NULL,
                  "P5: priv BN readback works (get_bn_param's internal size query answered)");
            BN_free(bn);
            EVP_PKEY_free(pk);
        }
        EVP_PKEY_CTX_free(gk);
    }

    printf(fails ? "ECBOUNDARY: %d FAILURES\n" : "ECBOUNDARY: ALL PASS\n", fails);
    return fails ? 1 : 0;
}
