/* guardtest.c: GCM nonce lifecycle under load.
 *
 * The Go module's TLS 1.3 GCM service (gcm_tls13.go) requires the record
 * counter to strictly increase per key. This suite drives it through EVP
 * in the TLS record pattern (key once, new IV per record):
 *
 *   I1 (no record cap): one key seals 70,000 records in order.
 *   I2 (no replay): a repeated nonce and an earlier nonce are refused at
 *      any point in the stream, and the stream continues afterwards.
 *   I3 (prefix): a nonce whose fixed 4-byte prefix differs from the first
 *      record's cannot belong to the stream and is refused.
 *   I4 (copy): a copied ctx shares the counter with its original.
 *   I5 (no key cap): 6,000 distinct keys each seal.
 *   I6 (concurrency): 8 threads, each with its own key, seal 5,000 records
 *      each without a failure, deadlock or crash.
 *
 * Usage: guardtest [dir containing gofips.so]   (default /tmp/modematrix)
 */
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <openssl/evp.h>
#include <openssl/provider.h>

static OSSL_LIB_CTX *G;
static EVP_CIPHER *gciph;
static int fails = 0;
#define CHECK(c, msg) do { if (!(c)) { printf("FAIL: %s\n", msg); fails++; } else printf("PASS: %s\n", msg); } while (0)

static const unsigned char IV12[12] = {9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9};

/* TLS 1.3 record nonce: the static IV XOR the sequence number */
static void seq_nonce(unsigned char nonce[12], unsigned long long seq) {
    memcpy(nonce, IV12, 12);
    for (int i = 0; i < 8; i++) nonce[11 - i] ^= (unsigned char)(seq >> (8 * i));
}

static EVP_CIPHER_CTX *keyed(const unsigned char *key) {
    EVP_CIPHER_CTX *x = EVP_CIPHER_CTX_new();
    if (!x || !EVP_EncryptInit_ex2(x, gciph, key, NULL, NULL)) return NULL;
    return x;
}

/* Seal one record. Returns 1 on success. */
static int seal_seq(EVP_CIPHER_CTX *x, const unsigned char nonce[12]) {
    unsigned char pt[16], ct[48];
    int l = 0;
    memset(pt, 'P', sizeof pt);
    return EVP_EncryptInit_ex2(x, NULL, NULL, nonce, NULL) &&
           EVP_EncryptUpdate(x, ct, &l, pt, 16) &&
           EVP_EncryptFinal_ex(x, ct + l, &l);
}

static void *worker(void *arg) {
    long id = (long)arg, bad = 0;
    unsigned char key[32], nonce[12];
    for (int i = 0; i < 32; i++) key[i] = (unsigned char)(id * 17 + i + 3);
    EVP_CIPHER_CTX *x = keyed(key);
    if (!x) return (void *)1L;
    for (unsigned long long s = 0; s < 5000; s++) {
        seq_nonce(nonce, s);
        if (!seal_seq(x, nonce)) bad++;
    }
    EVP_CIPHER_CTX_free(x);
    return (void *)bad;
}

int main(int argc, char **argv) {
    G = OSSL_LIB_CTX_new();
    OSSL_PROVIDER_set_default_search_path(G, argc > 1 ? argv[1] : "/tmp/modematrix");
    if (!OSSL_PROVIDER_load(G, "gofips")) { printf("LOAD FAIL\n"); return 3; }
    gciph = EVP_CIPHER_fetch(G, "AES-256-GCM", NULL);
    if (!gciph) { printf("FETCH FAIL\n"); return 3; }

    unsigned char key[32], nonce[12];
    for (int i = 0; i < 32; i++) key[i] = (unsigned char)(i + 1);

    /* I1 + I2: a long in-order stream, with replays attempted along the way */
    EVP_CIPHER_CTX *x = keyed(key);
    long sealed = 0, replay_ok = 0, back_ok = 0, resumed_bad = 0;
    for (unsigned long long s = 0; s < 70000; s++) {
        seq_nonce(nonce, s);
        if (seal_seq(x, nonce)) sealed++;
        if (s % 9973 == 9972) {
            if (seal_seq(x, nonce)) replay_ok++;            /* the same record again */
            seq_nonce(nonce, s - 100);
            if (seal_seq(x, nonce)) back_ok++;              /* an earlier record */
            seq_nonce(nonce, s + 1);                        /* the stream must go on */
            if (!seal_seq(x, nonce)) resumed_bad++;
            s++;
            sealed++;
        }
    }
    CHECK(sealed == 70000, "I1: 70000 in-order records sealed under one key (no per-key cap)");
    CHECK(replay_ok == 0, "I2: a repeated nonce is refused at every point tried");
    CHECK(back_ok == 0, "I2: an earlier nonce is refused at every point tried");
    CHECK(resumed_bad == 0, "I2: the stream continues with the next record after each refusal");

    /* I3: a nonce with a different fixed prefix is not part of this stream */
    seq_nonce(nonce, 80000);
    nonce[0] ^= 0x55;
    CHECK(!seal_seq(x, nonce), "I3: a nonce with a different 4-byte prefix is refused");
    seq_nonce(nonce, 80000);
    CHECK(seal_seq(x, nonce), "I3: the correct nonce for that record is still accepted");

    /* I4: a copy shares the counter */
    EVP_CIPHER_CTX *y = EVP_CIPHER_CTX_new();
    int rcopy = EVP_CIPHER_CTX_copy(y, x);
    seq_nonce(nonce, 80000);
    int r_old = rcopy ? seal_seq(y, nonce) : -1;
    seq_nonce(nonce, 80001);
    int r_new = rcopy ? seal_seq(y, nonce) : -1;
    int r_orig = seal_seq(x, nonce);
    CHECK(rcopy == 1 && r_old == 0, "I4: a copied ctx cannot re-seal a record its original sealed");
    CHECK(r_new == 1 && r_orig == 0, "I4: a record sealed through the copy is refused on the original");
    EVP_CIPHER_CTX_free(y);
    EVP_CIPHER_CTX_free(x);

    /* I5: many distinct keys in one process */
    long keys_ok = 0;
    for (int k = 0; k < 6000; k++) {
        unsigned char kk[32];
        memset(kk, 0, sizeof kk);
        kk[0] = (unsigned char)k; kk[1] = (unsigned char)(k >> 8); kk[2] = 0xA5;
        EVP_CIPHER_CTX *z = keyed(kk);
        seq_nonce(nonce, 0);
        if (z && seal_seq(z, nonce)) keys_ok++;
        EVP_CIPHER_CTX_free(z);
    }
    CHECK(keys_ok == 6000, "I5: 6000 distinct keys each sealed (no per-process key cap)");

    /* I6: concurrent streams, one key per thread */
    pthread_t th[8];
    long bad = 0;
    for (long i = 0; i < 8; i++) pthread_create(&th[i], NULL, worker, (void *)i);
    for (int i = 0; i < 8; i++) { void *r; pthread_join(th[i], &r); bad += (long)r; }
    CHECK(bad == 0, "I6: 8 threads x 5000 records, one key each, every record sealed");

    printf(fails ? "GUARDTEST: %d FAILURES\n" : "GUARDTEST: ALL PASS\n", fails);
    return fails ? 1 : 0;
}
