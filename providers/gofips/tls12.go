package main

// TLS 1.2 through the Go Cryptographic Module: the TLS 1.2 KDF (OpenSSL's
// TLS1-PRF) and AES-GCM record protection (RFC 5288).
//
// The module implements both: crypto/internal/fips140/tls12.PRF (SP
// 800-135 TLS 1.2 KDF, with its own CAST) and gcm.NewGCMForTLS12 (an SP
// 2.7 approved IV-generation API). crypto/tls reaches them through prf12
// and aeadAESGCM. Neither is exported, and unlike aeadAESGCMTLS13 neither
// carries a linkname marker, so the provider is linked with
// -ldflags=-checklinkname=0. testdata/tls12.c checks both against the
// default provider on every CI run, so a toolchain change that alters them
// fails the suites.
//
// The extended master secret (RFC 7627) is required: the KDF refuses the
// classic "master secret" derivation.

// #define OSSL_provider_init SUPPRESSED_OSSL_provider_init
// #include <openssl/core_dispatch.h>
// #undef OSSL_provider_init
// #include <openssl/core_names.h>
// #include <openssl/params.h>
//
// extern const OSSL_PARAM gofips_tls1prf_settable_ctx_params_tbl[5];
// extern const OSSL_PARAM gofips_tls1prf_gettable_ctx_params_tbl[2];
import "C"

import (
	"bytes"
	"crypto/cipher"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"hash"
	"math"
	"sync"
	"unsafe"
)

//go:linkname tlsPRF12 crypto/tls.prf12
func tlsPRF12(hashFunc func() hash.Hash) func(secret []byte, label string, seed []byte, keyLen int) []byte

// As with aeadAESGCMTLS13 (gcm_tls13.go): crypto/tls returns an unexported
// interface whose first four methods are cipher.AEAD's, in the same order.
//
//go:linkname tlsAEADAESGCM12 crypto/tls.aeadAESGCM
func tlsAEADAESGCM12(key, noncePrefix []byte) cipher.AEAD

// ---- TLS1-PRF ----

type tls1prfCtx struct {
	mu     sync.Mutex
	hashFn func() hash.Hash
	secret []byte
	seed   []byte
}

func regGetTLS1PRF(id uint64) *tls1prfCtx {
	c, _ := regGet(id).(*tls1prfCtx)
	return c
}

func (c *tls1prfCtx) wipe() {
	clear(c.secret)
	c.hashFn, c.secret, c.seed = nil, nil, nil
}

// tls12Digest: the TLS 1.2 KDF is approved with SHA-256, SHA-384 or
// SHA-512 (SP 800-135; the module's own check in tls12.MasterSecret).
func tls12Digest(name string) func() hash.Hash {
	fn, ok := approvedDigest(name)
	if !ok {
		return nil
	}
	switch h := fn(); {
	case h.Size() == 32 && h.BlockSize() == 64:
		return sha256.New
	case h.Size() == 48 && h.BlockSize() == 128:
		return sha512.New384
	case h.Size() == 64 && h.BlockSize() == 128:
		return sha512.New
	}
	return nil
}

//export gofips_tls1prf_newctx
func gofips_tls1prf_newctx(provctx *C.void) C.uint64_t {
	return handleGuard(func() C.uint64_t {
		_ = provctx
		return C.uint64_t(regPut(&tls1prfCtx{}))
	})
}

//export gofips_tls1prf_freectx
func gofips_tls1prf_freectx(kctx C.uint64_t) {
	if c := regGetTLS1PRF(uint64(kctx)); c != nil {
		withLock(&c.mu, c.wipe)
	}
	regDel(uint64(kctx))
}

//export gofips_tls1prf_reset
func gofips_tls1prf_reset(kctx C.uint64_t) {
	if c := regGetTLS1PRF(uint64(kctx)); c != nil {
		withLock(&c.mu, c.wipe)
	}
}

//export gofips_tls1prf_dupctx
func gofips_tls1prf_dupctx(src C.uint64_t) C.uint64_t {
	return handleGuard(func() C.uint64_t {
		s := regGetTLS1PRF(uint64(src))
		if s == nil {
			return 0
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		return C.uint64_t(regPut(&tls1prfCtx{
			hashFn: s.hashFn,
			secret: append([]byte(nil), s.secret...),
			seed:   append([]byte(nil), s.seed...),
		}))
	})
}

//export gofips_tls1prf_set_ctx_params
func gofips_tls1prf_set_ctx_params(kctx C.uint64_t, params *C.OSSL_PARAM) C.int {
	return opGuard(func() C.int {
		c := regGetTLS1PRF(uint64(kctx))
		if c == nil {
			return 0
		}
		return tls1prfSetParams(c, params)
	})
}

// As the default provider: a seed parameter appends to the seed (libssl
// passes the label and the seeds as several), a secret replaces it.
func tls1prfSetParams(c *tls1prfCtx, params *C.OSSL_PARAM) C.int {
	if params == nil {
		return 1
	}
	for i := 0; i < paramCount(params); i++ {
		p := paramAt(params, i)
		if p.key == nil {
			break
		}
		switch C.GoString(p.key) {
		case C.OSSL_KDF_PARAM_DIGEST:
			var dn string
			if !getUtf8Param(p, &dn) {
				return 0
			}
			fn := tls12Digest(dn)
			if fn == nil {
				dbg("tls1-prf REFUSED: digest %q (SHA-256, SHA-384 or SHA-512 only)", dn)
				return 0
			}
			withLock(&c.mu, func() { c.hashFn = fn })
		case C.OSSL_KDF_PARAM_SECRET:
			if p.data == nil && p.data_size > 0 {
				return 0
			}
			s := getOctetParam(p)
			withLock(&c.mu, func() { clear(c.secret); c.secret = append([]byte{}, s...) })
		case C.OSSL_KDF_PARAM_SEED:
			if p.data == nil && p.data_size > 0 {
				return 0
			}
			s := getOctetParam(p)
			withLock(&c.mu, func() { c.seed = append(c.seed, s...) })
		case C.OSSL_KDF_PARAM_PROPERTIES, "ems_check": // OSSL_KDF_PARAM_FIPS_EMS_CHECK (OpenSSL 3.4+ headers)
			// libssl asks for the EMS check; it is always on here.
		default:
			return 0
		}
	}
	return 1
}

var masterSecretLabel = []byte("master secret")

//export gofips_tls1prf_derive
func gofips_tls1prf_derive(kctx C.uint64_t, key *C.uchar, keylen C.size_t, params *C.OSSL_PARAM) C.int {
	return opGuard(func() C.int {
		c := regGetTLS1PRF(uint64(kctx))
		if c == nil || key == nil || keylen == 0 || uint64(keylen) > math.MaxInt32 {
			return 0
		}
		if tls1prfSetParams(c, params) != 1 {
			return 0
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		// 112 bits, as the module's other KDFs here; TLS secrets are 112
		// to 256 bits (SP 5247 Table 17).
		if c.hashFn == nil || len(c.secret) < 14 {
			return 0
		}
		// RFC 7627: the master secret must be the extended one.
		if bytes.HasPrefix(c.seed, masterSecretLabel) {
			dbg("tls1-prf REFUSED: master secret without the extended master secret extension")
			return 0
		}
		out := tlsPRF12(c.hashFn)(c.secret, "", c.seed, int(keylen))
		if len(out) != int(keylen) {
			return 0
		}
		copy(unsafe.Slice((*byte)(unsafe.Pointer(key)), int(keylen)), out)
		clear(out)
		recordOp("kdf")
		return 1
	})
}

//export gofips_tls1prf_settable_ctx_params
func gofips_tls1prf_settable_ctx_params(kctx C.uint64_t, provctx *C.void) *C.OSSL_PARAM {
	_, _ = kctx, provctx
	return (*C.OSSL_PARAM)(unsafe.Pointer(&C.gofips_tls1prf_settable_ctx_params_tbl[0]))
}

//export gofips_tls1prf_gettable_ctx_params
func gofips_tls1prf_gettable_ctx_params(kctx C.uint64_t, provctx *C.void) *C.OSSL_PARAM {
	_, _ = kctx, provctx
	return (*C.OSSL_PARAM)(unsafe.Pointer(&C.gofips_tls1prf_gettable_ctx_params_tbl[0]))
}

//export gofips_tls1prf_get_ctx_params
func gofips_tls1prf_get_ctx_params(kctx C.uint64_t, params *C.OSSL_PARAM) C.int {
	return opGuard(func() C.int {
		_ = kctx
		if params == nil {
			return 0
		}
		for i := 0; i < paramCount(params); i++ {
			p := paramAt(params, i)
			if p.key == nil {
				break
			}
			if C.GoString(p.key) == C.OSSL_KDF_PARAM_SIZE && !setUint(p, math.MaxUint64) {
				return 0
			}
		}
		return 1
	})
}

// ---- AES-GCM records (RFC 5288) ----

const (
	tls12ExplicitNonce = 8
	tls12Tag           = 16
	tls12AADLen        = 13
)

var errTLS12GCM = errors.New("tls1.2 gcm refused")

// tls12GCM is the module's TLS 1.2 GCM for one key in one direction. The
// explicit nonce of each sealed record is a counter from a random start;
// the module refuses a counter that does not increase. A
// provider ctx copy shares the instance, so the counter covers both.
type tls12GCM struct {
	mu     sync.Mutex
	aead   cipher.AEAD
	next   uint64
	broken bool
}

func newTLS12GCM(key, fixed []byte) (t *tls12GCM, err error) {
	defer func() {
		if recover() != nil {
			t, err = nil, errTLS12GCM
		}
	}()
	a := tlsAEADAESGCM12(key, fixed)
	if a.NonceSize() != tls12ExplicitNonce || a.Overhead() != tls12Tag {
		return nil, errTLS12GCM
	}
	// A random 63-bit start, as the default provider does: two instances
	// under one key (separate contexts given the same key) do not collide.
	var b [8]byte
	if _, err := cryptorand.Read(b[:]); err != nil {
		return nil, errTLS12GCM
	}
	return &tls12GCM{aead: a, next: binary.BigEndian.Uint64(b[:]) >> 1}, nil
}

// seal returns explicit nonce || ciphertext || tag.
func (t *tls12GCM) seal(aad, pt []byte) (rec []byte, err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.broken || t.next == math.MaxUint64 {
		return nil, errTLS12GCM
	}
	defer func() {
		if recover() != nil {
			t.broken, rec, err = true, nil, errTLS12GCM
		}
	}()
	rec = make([]byte, tls12ExplicitNonce, tls12ExplicitNonce+len(pt)+tls12Tag)
	binary.BigEndian.PutUint64(rec, t.next)
	rec = t.aead.Seal(rec, rec[:tls12ExplicitNonce], pt, aad)
	t.next++
	return rec, nil
}

func (t *tls12GCM) open(explicit, ct, aad []byte) (pt []byte, err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.broken {
		return nil, errTLS12GCM
	}
	defer func() {
		if recover() != nil {
			pt, err = nil, errTLS12GCM
		}
	}()
	return t.aead.Open(nil, explicit, ct, aad)
}

// tls12Record processes one TLS 1.2 record in place, as libssl passes it
// after setting the record's AAD: explicit nonce, data, tag. Callers hold
// ctx.mu.
func tls12Record(ctx *gcmCtx, out *C.uchar, outl *C.size_t, outsz C.size_t, in *C.uchar, inl C.size_t) C.int {
	aad := ctx.tlsAAD
	ctx.tlsAAD = nil
	n := int(inl)
	if out == nil || in == nil || n < tls12ExplicitNonce+tls12Tag || int(outsz) < n-tls12Tag {
		return 0
	}
	rec := append([]byte(nil), unsafe.Slice((*byte)(unsafe.Pointer(in)), n)...)
	if ctx.enc {
		if int(outsz) < n || int(binary.BigEndian.Uint16(aad[11:])) != n-tls12ExplicitNonce-tls12Tag {
			return 0
		}
		sealed, err := ctx.tls12.seal(aad, rec[tls12ExplicitNonce:n-tls12Tag])
		if err != nil || len(sealed) != n {
			return 0
		}
		copy(unsafe.Slice((*byte)(unsafe.Pointer(out)), n), sealed)
		*outl = C.size_t(n)
		recordOp("cipher")
		return 1
	}
	pt, err := ctx.tls12.open(rec[:tls12ExplicitNonce], rec[tls12ExplicitNonce:], aad)
	if err != nil {
		return 0
	}
	copy(unsafe.Slice((*byte)(unsafe.Pointer(out)), n)[tls12ExplicitNonce:], pt)
	*outl = C.size_t(len(pt))
	recordOp("cipher")
	return 1
}
