/* config_pref.c: the shipped gofips config, against the OpenSSL it is
 * built for. The config activates gofips and base and prefers gofips
 * (default_properties = ?provider=gofips). Wolfi's OpenSSL 3.6 base also
 * serves SHA-1 and MD5; this checks that, whichever OpenSSL loads it:
 *
 *   - SHA-1 resolves to gofips, with the right answer;
 *   - MD5 computes nothing. On an OpenSSL 3 core, gofips registers a
 *     refused MD5, so a fetch returns gofips's and every use fails; on
 *     OpenSSL 4 a fetch returns nothing;
 *   - SHA-256 resolves to gofips;
 *   - a PEM private and public key load (base's decoders).
 *
 * Build:  cc -o config_pref config_pref.c $(pkg-config --cflags --libs openssl)
 * Run:    OPENSSL_CONF=<shipped config, module path set> GODEBUG=fips140=on ./config_pref
 */
#include <stdio.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/provider.h>

static int fails = 0;
#define CHECK(cond, ...) do { if (cond) { printf("PASS: " __VA_ARGS__); printf("\n"); } \
    else { printf("FAIL: " __VA_ARGS__); printf("\n"); fails++; } } while (0)

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

static const char *provider_of(const char *alg) {
    EVP_MD *md = EVP_MD_fetch(NULL, alg, NULL);
    static char name[64];
    if (md == NULL)
        return NULL;
    snprintf(name, sizeof name, "%s", OSSL_PROVIDER_get0_name(EVP_MD_get0_provider(md)));
    EVP_MD_free(md);
    return name;
}

static int digest_hex(const char *alg, char *out) {
    unsigned char md[EVP_MAX_MD_SIZE];
    size_t n = 0;
    if (!EVP_Q_digest(NULL, alg, NULL, "abc", 3, md, &n))
        return 0;
    for (size_t i = 0; i < n; i++)
        sprintf(out + 2 * i, "%02x", md[i]);
    return 1;
}

int main(void) {
    int ossl3 = OPENSSL_VERSION_MAJOR == 3;
    char h[2 * EVP_MAX_MD_SIZE + 1] = "";
    const char *p;

    printf("OpenSSL %s\n", OpenSSL_version(OPENSSL_VERSION_STRING));
    /* Load OPENSSL_CONF before any provider query, which would otherwise
     * activate the default provider. */
    CHECK(OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL) == 1, "OPENSSL_CONF loads");
    CHECK(OSSL_PROVIDER_available(NULL, "gofips") && OSSL_PROVIDER_available(NULL, "base")
          && !OSSL_PROVIDER_available(NULL, "default"), "gofips and base are loaded, default is not");

    p = provider_of("SHA1");
    CHECK(p && strcmp(p, "gofips") == 0, "SHA-1 resolves to gofips (%s)", p ? p : "none");
    CHECK(digest_hex("SHA1", h) && strcmp(h, "a9993e364706816aba3e25717850c26c9cd0d89d") == 0,
          "SHA-1(\"abc\") known answer");
    p = provider_of("SHA2-256");
    CHECK(p && strcmp(p, "gofips") == 0, "SHA-256 resolves to gofips (%s)", p ? p : "none");

    h[0] = 0;
    CHECK(!digest_hex("MD5", h), "MD5 computes nothing");
    p = provider_of("MD5");
    if (ossl3)
        CHECK(p && strcmp(p, "gofips") == 0, "OpenSSL 3: an MD5 fetch returns gofips's refused MD5 (%s)",
              p ? p : "none");
    else
        CHECK(p == NULL, "OpenSSL 4: an MD5 fetch returns nothing (%s)", p ? p : "none");
    EVP_MD *md5 = EVP_MD_fetch(NULL, "MD5", NULL);
    if (md5 != NULL) {
        EVP_MD_CTX *c = EVP_MD_CTX_new();
        CHECK(c && !EVP_DigestInit_ex(c, md5, NULL), "MD5: EVP_DigestInit_ex refuses");
        EVP_MD_CTX_free(c);
        EVP_MD_free(md5);
    }

    BIO *b = BIO_new_mem_buf(P256_PRIV, -1);
    EVP_PKEY *k = PEM_read_bio_PrivateKey_ex(b, NULL, NULL, NULL, NULL, NULL);
    CHECK(k != NULL, "a PEM P-256 private key loads");
    EVP_PKEY_free(k);
    BIO_free(b);
    b = BIO_new_mem_buf(P256_PUB, -1);
    k = PEM_read_bio_PUBKEY_ex(b, NULL, NULL, NULL, NULL, NULL);
    CHECK(k != NULL, "a PEM P-256 public key loads");
    EVP_PKEY_free(k);
    BIO_free(b);

    printf(fails ? "CONFIGPREF: %d FAILED\n" : "CONFIGPREF: ALL PASS\n", fails);
    return fails != 0;
}
