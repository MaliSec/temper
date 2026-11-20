/* panictest.c - panic-containment gate.
 *
 * Drives each exported family with panic-shaped inputs (nil pointers,
 * zero lengths, invalid params). The host process must survive every
 * probe with an EVP error, never a signal; a crash leaves a nonzero exit
 * and no final line.
 *
 * Each family section is marked "---- <family> family ----";
 * coverage-check.sh matches these markers against
 * panictest-inventory.txt (see coverage-inventory.sh).
 *
 * Usage: panictest <dir containing gofips.so>
 */
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/provider.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>

static OSSL_LIB_CTX *G;
static int steps = 0;

/* A crash in the call aborts before "survived" is printed. */
#define PROBE(desc, call) do { steps++; fprintf(stderr, "probe %d: %s\n", steps, desc); fflush(stderr); (void)(call); printf("  survived: %s\n", desc); } while (0)

int main(int argc, char **argv) {
    G = OSSL_LIB_CTX_new();
    OSSL_PROVIDER_set_default_search_path(G, argv[1]);
    if (!OSSL_PROVIDER_load(G, "gofips")) { printf("LOAD FAIL\n"); return 3; }

    /* ---- digest family ---- */
    EVP_MD *md = EVP_MD_fetch(G, "SHA256", NULL);
    EVP_MD_CTX *m = EVP_MD_CTX_new();
    PROBE("digest update nil-in on live ctx", EVP_DigestUpdate(m, NULL, 0));
    PROBE("digest update nonnil-in zerolen", EVP_DigestUpdate(m, "x", 0));
    PROBE("digest final nil-outl", EVP_DigestFinal_ex(m, NULL, NULL));
    PROBE("digest on hostile ctx via fetch-free path", EVP_MD_get_size(md));
    EVP_MD_CTX_free(m);
    EVP_MD_free(md);

    /* ---- mac family ---- */
    EVP_MAC *mac = EVP_MAC_fetch(G, "HMAC", NULL);
    EVP_MAC_CTX *mc = EVP_MAC_CTX_new(mac);
    OSSL_PARAM kp[3] = { OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0),
                         OSSL_PARAM_construct_octet_string("key", (void *)"0123456789abcdef0123", 20),
                         OSSL_PARAM_construct_end() };
    PROBE("mac init nil key with params", EVP_MAC_init(mc, NULL, 0, kp));
    PROBE("mac init short key", EVP_MAC_init(mc, (const unsigned char *)"ab", 2, kp));
    PROBE("mac update nil", EVP_MAC_update(mc, NULL, 4));
    PROBE("mac final nil outl", EVP_MAC_final(mc, NULL, NULL, 32));
    EVP_MAC_CTX *mcd = EVP_MAC_CTX_dup(mc);
    PROBE("mac dup of live ctx usable", mcd ? EVP_MAC_update(mcd, (const unsigned char *)"z", 1) : 0);
    EVP_MAC_CTX_free(mcd);
    EVP_MAC_CTX_free(mc);
    EVP_MAC_free(mac);

    /* ---- kdf family ---- */
    EVP_KDF *kdf = EVP_KDF_fetch(G, "HKDF", NULL);
    EVP_KDF_CTX *kc = EVP_KDF_CTX_new(kdf);
    OSSL_PARAM kd[3] = { OSSL_PARAM_construct_octet_string("key", (void *)"0123456789abcdef0123456789abcdef", 32),
                         OSSL_PARAM_construct_octet_string("salt", (void *)"salt", 4),
                         OSSL_PARAM_construct_end() };
    unsigned char kb[32];
    PROBE("kdf derive nil key buf", EVP_KDF_derive(kc, NULL, 32, kd));
    PROBE("kdf derive zero len", EVP_KDF_derive(kc, kb, 0, kd));
    PROBE("kdf derive short ikm (below 112-bit floor)", EVP_KDF_derive(kc, kb, 32, kd));
    EVP_KDF_CTX_free(kc);
    EVP_KDF_free(kdf);

    /* ---- tls13kdf family ---- */
    EVP_KDF *t13 = EVP_KDF_fetch(G, "TLS13-KDF", NULL);
    EVP_KDF_CTX *tc = EVP_KDF_CTX_new(t13);
    OSSL_PARAM td[2] = { OSSL_PARAM_construct_octet_string("key", (void *)"0123456789abcdef0123456789abcdef", 32),
                         OSSL_PARAM_construct_end() };
    PROBE("tls13kdf derive nil key buf", EVP_KDF_derive(tc, NULL, 32, td));
    PROBE("tls13kdf derive zero len", EVP_KDF_derive(tc, kb, 0, td));
    EVP_KDF_CTX_free(tc);
    EVP_KDF_free(t13);

    /* ---- cipher family ---- */
    EVP_CIPHER *ci = EVP_CIPHER_fetch(G, "AES-256-GCM", NULL);
    EVP_CIPHER_CTX *cc = EVP_CIPHER_CTX_new();
    unsigned char key32[32]; memset(key32, 1, 32);
    unsigned char iv12[12]; memset(iv12, 9, 12);
    unsigned char ct[64]; int l = 0;
    PROBE("cipher update nil-outl", EVP_EncryptUpdate(cc, ct, NULL, (const unsigned char *)"a", 1));
    PROBE("cipher update nil-in nonnil-len", EVP_EncryptUpdate(cc, ct, &l, NULL, 4));
    PROBE("cipher final nil outl", EVP_EncryptFinal_ex(cc, NULL, NULL));
    PROBE("cipher set tag nil", EVP_CIPHER_CTX_ctrl(cc, EVP_CTRL_AEAD_SET_TAG, 16, NULL));
    PROBE("cipher get tag small buf", EVP_CIPHER_CTX_ctrl(cc, EVP_CTRL_AEAD_GET_TAG, 4, ct));
    /* TLS 1.2 record mode */
    unsigned char aad13[13] = {0, 0, 0, 0, 0, 0, 0, 1, 23, 3, 3, 0, 4};
    PROBE("tls12 aad before the fixed iv", EVP_EncryptInit_ex(cc, ci, NULL, key32, NULL) &&
                                           EVP_CIPHER_CTX_ctrl(cc, EVP_CTRL_AEAD_TLS1_AAD, 13, aad13));
    PROBE("tls12 fixed iv of 12 bytes", EVP_CIPHER_CTX_ctrl(cc, EVP_CTRL_GCM_SET_IV_FIXED, 12, iv12));
    PROBE("tls12 short aad", EVP_CIPHER_CTX_ctrl(cc, EVP_CTRL_GCM_SET_IV_FIXED, 4, iv12) &&
                             EVP_CIPHER_CTX_ctrl(cc, EVP_CTRL_AEAD_TLS1_AAD, 5, aad13));
    PROBE("tls12 record shorter than nonce and tag", EVP_CIPHER_CTX_ctrl(cc, EVP_CTRL_AEAD_TLS1_AAD, 13, aad13) > 0 &&
                                                     EVP_EncryptUpdate(cc, ct, &l, ct, 10));
    PROBE("tls12 aad length disagrees with the record", EVP_CIPHER_CTX_ctrl(cc, EVP_CTRL_AEAD_TLS1_AAD, 13, aad13) > 0 &&
                                                        EVP_EncryptUpdate(cc, ct, &l, ct, 64));
    EVP_CIPHER_CTX_free(cc);
    EVP_CIPHER_free(ci);

    /* ---- keymgmt family ---- */
    EVP_PKEY_CTX *pc = EVP_PKEY_CTX_new_from_name(G, "EC", NULL);
    PROBE("keymgmt fromdata nil params", EVP_PKEY_fromdata(pc, NULL, 0, NULL));
    EVP_PKEY_CTX_free(pc);
    PROBE("keymgmt gen hostile (EVP_PKEY_Q_keygen EC)", (EVP_PKEY_Q_keygen(G, NULL, "EC", "prime256v1") != NULL));
    EVP_PKEY *somek = EVP_PKEY_Q_keygen(G, NULL, "EC", "prime256v1");
    OSSL_PARAM *exp = NULL;
    PROBE("keymgmt export todata", EVP_PKEY_todata(somek, OSSL_KEYMGMT_SELECT_ALL, &exp));
    if (exp) OSSL_PARAM_free(exp);
    EVP_PKEY_free(somek);

    /* ---- keyexch family ---- */
    EVP_PKEY *kA = EVP_PKEY_Q_keygen(G, NULL, "EC", "prime256v1");
    EVP_PKEY_CTX *ec = EVP_PKEY_CTX_new_from_pkey(G, kA, NULL);
    size_t sl = 0;
    PROBE("keyexch derive with no peer", EVP_PKEY_derive(ec, NULL, &sl));
    EVP_PKEY_CTX_free(ec);
    EVP_PKEY_free(kA);

    /* ---- sig family ---- */
    EVP_PKEY *sk = EVP_PKEY_Q_keygen(G, NULL, "EC", "prime256v1");
    EVP_MD_CTX *sm = EVP_MD_CTX_new();
    int sinit = EVP_DigestSignInit(sm, NULL, EVP_sha256(), NULL, sk);
    unsigned char sig[96]; size_t siglen = sizeof sig;
    PROBE("sig digestsign nil msg (after init)", sinit > 0 && EVP_DigestSign(sm, sig, &siglen, NULL, 0));
    EVP_MD_CTX_free(sm);
    /* DigestSign on an uninitialized ctx segfaults inside libcrypto 3.0
     * before reaching the provider, so it is not probed. */
    EVP_MD_CTX *vm = EVP_MD_CTX_new();
    PROBE("sig digestverify nil sig", EVP_DigestVerifyInit(vm, NULL, EVP_sha256(), NULL, sk) > 0 &&
                                       EVP_DigestVerify(vm, NULL, 0, (const unsigned char *)"m", 1));
    EVP_MD_CTX_free(vm);
    EVP_PKEY_free(sk);

    /* ---- sha3 family ---- */
    EVP_MD *s3 = EVP_MD_fetch(G, "SHA3-256", NULL), *shk = EVP_MD_fetch(G, "SHAKE-256", NULL);
    EVP_MD_CTX *s3m = EVP_MD_CTX_new();
    unsigned char s3o[64];
    PROBE("sha3 update nil-in zerolen", EVP_DigestInit_ex(s3m, s3, NULL) && EVP_DigestUpdate(s3m, NULL, 0));
    PROBE("sha3 final nil outl", EVP_DigestFinal_ex(s3m, s3o, NULL));
    PROBE("shake final without an output length", EVP_DigestInit_ex(s3m, shk, NULL) && EVP_DigestFinal_ex(s3m, s3o, NULL));
    PROBE("shake final xof zero length", EVP_DigestInit_ex(s3m, shk, NULL) && EVP_DigestFinalXOF(s3m, s3o, 0));
    EVP_MD_CTX_free(s3m);
    EVP_MD_free(s3);
    EVP_MD_free(shk);

    /* ---- pbkdf2 family ---- */
    EVP_KDF *pb = EVP_KDF_fetch(G, "PBKDF2", NULL);
    EVP_KDF_CTX *pbc = EVP_KDF_CTX_new(pb);
    OSSL_PARAM pbp[4] = { OSSL_PARAM_construct_octet_string("pass", (void *)"password", 8),
                          OSSL_PARAM_construct_octet_string("salt", (void *)"s", 1),
                          OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0),
                          OSSL_PARAM_construct_end() };
    PROBE("pbkdf2 derive nil key buf", EVP_KDF_derive(pbc, NULL, 32, pbp));
    PROBE("pbkdf2 derive zero len", EVP_KDF_derive(pbc, kb, 0, pbp));
    PROBE("pbkdf2 derive one-byte salt", EVP_KDF_derive(pbc, kb, 32, pbp));
    EVP_KDF_CTX *pbd = EVP_KDF_CTX_dup(pbc);
    PROBE("pbkdf2 dup of a configured ctx", pbd ? EVP_KDF_derive(pbd, kb, 32, NULL) : 0);
    EVP_KDF_CTX_free(pbd);
    EVP_KDF_CTX_free(pbc);
    EVP_KDF_free(pb);

    /* ---- rsa-keymgmt family ---- */
    unsigned char nb[256];
    memset(nb, 0xa5, sizeof nb);
    nb[0] = 0xc1; nb[255] |= 1;
    BIGNUM *bn_n = BN_bin2bn(nb, sizeof nb, NULL), *bn_e = BN_new();
    BN_set_word(bn_e, 65537);
    unsigned char nle[256], ele[3] = {0x01, 0x00, 0x01};
    BN_bn2nativepad(bn_n, nle, sizeof nle);
    OSSL_PARAM rp[3] = { OSSL_PARAM_construct_BN("n", nle, sizeof nle), OSSL_PARAM_construct_BN("e", ele, sizeof ele),
                         OSSL_PARAM_construct_end() };
    OSSL_PARAM rp_n[2] = { OSSL_PARAM_construct_BN("n", nle, sizeof nle), OSSL_PARAM_construct_end() };
    EVP_PKEY_CTX *rc = EVP_PKEY_CTX_new_from_name(G, "RSA", NULL);
    EVP_PKEY *rk = NULL, *rk2 = NULL;
    PROBE("rsa-keymgmt fromdata nil params", EVP_PKEY_fromdata_init(rc) && EVP_PKEY_fromdata(rc, &rk2, EVP_PKEY_PUBLIC_KEY, NULL));
    PROBE("rsa-keymgmt fromdata without e", EVP_PKEY_fromdata(rc, &rk2, EVP_PKEY_PUBLIC_KEY, rp_n));
    PROBE("rsa-keymgmt fromdata public key", EVP_PKEY_fromdata(rc, &rk, EVP_PKEY_PUBLIC_KEY, rp));
    PROBE("rsa-keymgmt fromdata as a key pair", EVP_PKEY_fromdata(rc, &rk2, EVP_PKEY_KEYPAIR, rp));
    OSSL_PARAM *rexp = NULL;
    PROBE("rsa-keymgmt export todata", rk && EVP_PKEY_todata(rk, OSSL_KEYMGMT_SELECT_ALL, &rexp));
    OSSL_PARAM_free(rexp);
    BIGNUM *rbn = NULL;
    PROBE("rsa-keymgmt get n", rk && EVP_PKEY_get_bn_param(rk, "n", &rbn));
    BN_free(rbn);
    PROBE("rsa-keymgmt keygen", EVP_PKEY_Q_keygen(G, NULL, "RSA", (size_t)2048) != NULL);
    EVP_PKEY_CTX_free(rc);
    EVP_PKEY_free(rk2);

    /* ---- rsa-sig family ---- */
    EVP_MD_CTX *rv = EVP_MD_CTX_new();
    PROBE("rsa-sig digestverify nil sig", rk && EVP_DigestVerifyInit_ex(rv, NULL, "SHA2-256", G, NULL, rk, NULL) > 0
                                         && EVP_DigestVerify(rv, NULL, 0, (const unsigned char *)"m", 1));
    PROBE("rsa-sig digestverify garbage sig", rk && EVP_DigestVerifyInit_ex(rv, NULL, "SHA2-256", G, NULL, rk, NULL) > 0
                                             && EVP_DigestVerify(rv, nb, sizeof nb, (const unsigned char *)"m", 1));
    PROBE("rsa-sig update nil-in nonzero len", rk && EVP_DigestVerifyInit_ex(rv, NULL, "SHA2-256", G, NULL, rk, NULL) > 0
                                              && EVP_DigestVerifyUpdate(rv, NULL, 4));
    PROBE("rsa-sig final nil sig", EVP_DigestVerifyFinal(rv, NULL, 0));
    EVP_MD_CTX_free(rv);
    EVP_PKEY_CTX *rvc = rk ? EVP_PKEY_CTX_new_from_pkey(G, rk, NULL) : NULL;
    PROBE("rsa-sig verify with no digest set", rvc && EVP_PKEY_verify_init(rvc) && EVP_PKEY_verify(rvc, nb, sizeof nb, nb, 32));
    PROBE("rsa-sig pss saltlen junk", rvc && EVP_PKEY_CTX_set_rsa_padding(rvc, RSA_PKCS1_PSS_PADDING) > 0
                                      && EVP_PKEY_CTX_set_rsa_pss_saltlen(rvc, -99));
    PROBE("rsa-sig sign init", rvc && EVP_PKEY_sign_init(rvc));
    EVP_PKEY_CTX_free(rvc);
    EVP_PKEY_free(rk);
    BN_free(bn_n);
    BN_free(bn_e);

    /* ---- tls1prf family ---- */
    EVP_KDF *prfk = EVP_KDF_fetch(G, "TLS1-PRF", NULL);
    EVP_KDF_CTX *prfc = prfk ? EVP_KDF_CTX_new(prfk) : NULL;
    unsigned char prfo[48];
    OSSL_PARAM prfp[4] = {OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, "SHA2-256", 0),
                        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SECRET, NULL, 0),
                        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SEED, NULL, 0), OSSL_PARAM_construct_end()};
    PROBE("tls1prf derive with nothing set", prfc && EVP_KDF_derive(prfc, prfo, sizeof prfo, NULL));
    PROBE("tls1prf derive empty secret and seed", prfc && EVP_KDF_derive(prfc, prfo, sizeof prfo, prfp));
    PROBE("tls1prf derive zero length", prfc && EVP_KDF_derive(prfc, prfo, 0, prfp));
    PROBE("tls1prf nil-data seed with a size", (prfp[2] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SEED, NULL, 9),
                                               prfc && EVP_KDF_CTX_set_params(prfc, prfp)));
    PROBE("tls1prf dup and reset", (EVP_KDF_CTX_free(prfc ? EVP_KDF_CTX_dup(prfc) : NULL), prfc ? (EVP_KDF_CTX_reset(prfc), 0) : 0));
    EVP_KDF_CTX_free(prfc);
    EVP_KDF_free(prfk);

    /* ---- hmac-keymgmt family ---- */
    static const unsigned char hk[32] = "an HMAC key of thirty-two bytes";
    EVP_PKEY *hkey = EVP_PKEY_new_raw_private_key_ex(G, "HMAC", NULL, hk, sizeof hk);
    EVP_PKEY *hshort = EVP_PKEY_new_raw_private_key_ex(G, "HMAC", NULL, hk, 4);
    PROBE("hmac-keymgmt empty key", (EVP_PKEY_free(EVP_PKEY_new_raw_private_key_ex(G, "HMAC", NULL, NULL, 0)), 0));
    PROBE("hmac-keymgmt export", hkey && EVP_PKEY_get_raw_private_key(hkey, nb, &(size_t){sizeof nb}));
    PROBE("hmac-keymgmt eq", hkey && hshort && EVP_PKEY_eq(hkey, hshort));
    PROBE("hmac-keymgmt dup", (EVP_PKEY_free(hkey ? EVP_PKEY_dup(hkey) : NULL), 0));

    /* ---- hmac-sig family ---- */
    EVP_MD_CTX *hs = EVP_MD_CTX_new();
    size_t hl = sizeof nb;
    PROBE("hmac-sig short key", hshort && EVP_DigestSignInit_ex(hs, NULL, "SHA2-256", G, NULL, hshort, NULL));
    PROBE("hmac-sig sha1", hkey && EVP_DigestSignInit_ex(hs, NULL, "SHA1", G, NULL, hkey, NULL));
    PROBE("hmac-sig no digest", hkey && EVP_DigestSignInit_ex(hs, NULL, NULL, G, NULL, hkey, NULL));
    PROBE("hmac-sig update nil-in nonzero len", hkey && EVP_DigestSignInit_ex(hs, NULL, "SHA2-256", G, NULL, hkey, NULL) > 0
                                               && EVP_DigestSignUpdate(hs, NULL, 4));
    PROBE("hmac-sig final small buffer", hkey && EVP_DigestSignInit_ex(hs, NULL, "SHA2-256", G, NULL, hkey, NULL) > 0
                                        && EVP_DigestSignFinal(hs, nb, &(size_t){4}));
    PROBE("hmac-sig final", hkey && EVP_DigestSignInit_ex(hs, NULL, "SHA2-256", G, NULL, hkey, NULL) > 0
                            && EVP_DigestSignFinal(hs, nb, &hl));
    PROBE("hmac-sig verify init", hkey && EVP_DigestVerifyInit_ex(hs, NULL, "SHA2-256", G, NULL, hkey, NULL));
    EVP_MD_CTX_free(hs);
    EVP_PKEY_free(hkey);
    EVP_PKEY_free(hshort);

    /* ---- rand family ---- */
    EVP_RAND *rnd = EVP_RAND_fetch(G, "CTR-DRBG", NULL);
    EVP_RAND_CTX *rc2 = EVP_RAND_CTX_new(rnd, NULL);
    unsigned char rb[16];
    PROBE("rand generate with real ctx", EVP_RAND_generate(rc2, rb, sizeof rb, 0, 0, NULL, 0));
    PROBE("rand generate nil buf nonzero len", EVP_RAND_generate(rc2, NULL, 8, 0, 0, NULL, 0));
    EVP_RAND_CTX_free(rc2);
    EVP_RAND_free(rnd);

    /* ---- provider family ---- */
    /* random_bytes has no public entry point; only get_params is probed. */
    OSSL_PROVIDER *prov = OSSL_PROVIDER_load(G, "gofips");
    OSSL_PARAM gp[2] = { OSSL_PARAM_construct_end() };
    PROBE("provider get_params empty", OSSL_PROVIDER_get_params(prov, gp));
    OSSL_PROVIDER_unload(prov);

    printf("PANICTEST: %d probes, host alive\n", steps);
    return 0;
}
