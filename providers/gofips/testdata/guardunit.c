/* guardunit.c: the caller-visible GCM contract, on the release artifact.
 *
 * GCM is served by the Go module's TLS 1.3 GCM service (gcm_tls13.go).
 * These are the return codes a caller sees:
 *
 *   U1  a first seal succeeds and equals the default provider byte for byte
 *   U2  the same nonce again on the same ctx is refused
 *   U3  the same nonce through a copy of the ctx is refused
 *   U4  the next record's nonce is accepted, also after a refusal
 *   U5  a different key seals independently under the same nonce
 *   U6  decrypt returns the plaintext; a wrong tag is refused
 *   U7  both GCM algorithms are fetchable with fips=yes; AES-256-CBC is not
 *
 * Which code refuses a replay is shown separately by guardunit-attrib.sh
 * (debug trace) and by the Go unit test gcm_tls13_test.go, which also
 * proves the module itself refuses when the adapter's check is bypassed.
 *
 * Usage: guardunit <dir containing gofips.so>
 */
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/provider.h>

static OSSL_LIB_CTX *G, *D;
static int fails = 0;
#define CHECK(c, msg) do { if (!(c)) { printf("FAIL: %s\n", msg); fails++; } else printf("PASS: %s\n", msg); } while (0)

static const unsigned char IV12[12] = {9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9};

static void seq_nonce(unsigned char nonce[12], unsigned long long seq) {
    memcpy(nonce, IV12, 12);
    for (int i = 0; i < 8; i++) nonce[11 - i] ^= (unsigned char)(seq >> (8 * i));
}

/* one record on an already-keyed ctx; ct gets 16 bytes, tag 16 bytes */
static int seal(EVP_CIPHER_CTX *x, const unsigned char nonce[12], unsigned char *ct, unsigned char *tag) {
    unsigned char pt[16];
    int l = 0;
    memset(pt, 'P', sizeof pt);
    return EVP_EncryptInit_ex2(x, NULL, NULL, nonce, NULL) &&
           EVP_EncryptUpdate(x, ct, &l, pt, 16) &&
           EVP_EncryptFinal_ex(x, ct + l, &l) &&
           EVP_CIPHER_CTX_ctrl(x, EVP_CTRL_AEAD_GET_TAG, 16, tag);
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <dir containing gofips.so>\n", argv[0]); return 2; }
    G = OSSL_LIB_CTX_new(); D = OSSL_LIB_CTX_new();
    OSSL_PROVIDER_set_default_search_path(G, argv[1]);
    if (!OSSL_PROVIDER_load(G, "gofips")) { printf("LOAD FAIL\n"); return 3; }
    if (!OSSL_PROVIDER_load(D, "default")) { printf("DEFAULT LOAD FAIL\n"); return 3; }
    EVP_CIPHER *cg = EVP_CIPHER_fetch(G, "AES-256-GCM", NULL);
    EVP_CIPHER *cd = EVP_CIPHER_fetch(D, "AES-256-GCM", NULL);

    unsigned char key[32], key2[32], n0[12], n1[12];
    unsigned char ct[32], tag[16], ctd[32], tagd[16], scratch[32], stag[16];
    for (int i = 0; i < 32; i++) { key[i] = (unsigned char)(i + 1); key2[i] = (unsigned char)(i + 41); }
    seq_nonce(n0, 0); seq_nonce(n1, 1);

    EVP_CIPHER_CTX *x = EVP_CIPHER_CTX_new(), *d = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex2(x, cg, key, NULL, NULL);
    EVP_EncryptInit_ex2(d, cd, key, NULL, NULL);

    /* U1 */
    int rg = seal(x, n0, ct, tag), rd = seal(d, n0, ctd, tagd);
    CHECK(rg == 1 && rd == 1 && !memcmp(ct, ctd, 16) && !memcmp(tag, tagd, 16),
          "U1: first seal succeeds; ciphertext and tag equal the default provider's");

    /* U2 */
    CHECK(seal(x, n0, scratch, stag) == 0, "U2: the same nonce again on the same ctx is refused");

    /* U3 */
    EVP_CIPHER_CTX *y = EVP_CIPHER_CTX_new();
    int rcopy = EVP_CIPHER_CTX_copy(y, x);
    CHECK(rcopy == 1 && seal(y, n0, scratch, stag) == 0, "U3: the same nonce through a copy of the ctx is refused");

    /* U4 */
    int r1g = seal(x, n1, ct, tag), r1d = seal(d, n1, ctd, tagd);
    CHECK(r1g == 1 && r1d == 1 && !memcmp(ct, ctd, 16) && !memcmp(tag, tagd, 16),
          "U4: the next record is accepted after the refusals, and equals the default provider's");

    /* U5 */
    EVP_CIPHER_CTX *k2 = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex2(k2, cg, key2, NULL, NULL);
    CHECK(seal(k2, n0, scratch, stag) == 1, "U5: a different key seals independently under the same nonce");

    /* U6: decrypt record 1 (tag before data, the TLS order) */
    unsigned char out[32];
    int l = 0;
    EVP_CIPHER_CTX *o = EVP_CIPHER_CTX_new();
    int ro = EVP_DecryptInit_ex2(o, cg, key, n1, NULL) &&
             EVP_CIPHER_CTX_ctrl(o, EVP_CTRL_AEAD_SET_TAG, 16, tag) &&
             EVP_DecryptUpdate(o, out, &l, ct, 16) &&
             EVP_DecryptFinal_ex(o, out + l, &l);
    unsigned char want[16];
    memset(want, 'P', sizeof want);
    CHECK(ro == 1 && !memcmp(out, want, 16), "U6: decrypt returns the plaintext");
    unsigned char bad[16];
    memcpy(bad, tag, 16); bad[15] ^= 1;
    EVP_CIPHER_CTX *o2 = EVP_CIPHER_CTX_new();
    int rb = EVP_DecryptInit_ex2(o2, cg, key, n1, NULL) &&
             EVP_CIPHER_CTX_ctrl(o2, EVP_CTRL_AEAD_SET_TAG, 16, bad) &&
             EVP_DecryptUpdate(o2, out, &l, ct, 16);
    CHECK(rb == 0, "U6: a wrong tag is refused");

    /* U7: the property label. GCM runs through the module's TLS 1.3 GCM,
     * an approved IV API in SP 2.7, and carries fips=yes; CBC does not. */
    EVP_CIPHER *f256 = EVP_CIPHER_fetch(G, "AES-256-GCM", "fips=yes");
    EVP_CIPHER *f128 = EVP_CIPHER_fetch(G, "AES-128-GCM", "fips=yes");
    EVP_CIPHER *fcbc = EVP_CIPHER_fetch(G, "AES-256-CBC", "fips=yes");
    CHECK(f256 != NULL && f128 != NULL, "U7: AES-256-GCM and AES-128-GCM are fetchable with fips=yes");
    CHECK(fcbc == NULL, "U7: AES-256-CBC is not fetchable with fips=yes");
    EVP_CIPHER_free(f256); EVP_CIPHER_free(f128); EVP_CIPHER_free(fcbc);

    printf(fails ? "GUARDUNIT: %d FAILURES\n" : "GUARDUNIT: ALL PASS\n", fails);
    return fails ? 1 : 0;
}
