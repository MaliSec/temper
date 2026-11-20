package main

// tls.go, TLS-surface operations for the gofips provider: SHA-1/256/384/512,
// HMAC, HKDF, TLS13-KDF, AES-GCM (non-streaming, see below), AES-128/256-CBC,
// EC key management (P-256, P-384), ECDH key exchange, and ECDSA signatures.
// Approved operations route to the Go Cryptographic Module (CMVP #5247);
// SHA-1 (fips=no) does not. GCM record protection goes through
// gcm_tls13.go and tls12.go.
//
// Exclusive-routing design: unregistered algorithms fail closed (the
// default provider is absent in the gofips-only config).
//
// SHA-3, SHAKE and PBKDF2 are in kdf_sha3.go, RSA verification in rsa.go.
// Not registered (fetch fails closed): SHA-224, ChaCha20-Poly1305, RSA
// signing and encryption, DH/FFDHE, DSA, ML-KEM.
//   - AES-GCM is registered as a non-streaming one-shot implementation:
//     exactly one data update per nonce; a second data update is
//     refused and cipher_final fails closed.
//   - AES-256-CBC and AES-128-CBC (PKCS#7) encrypt TLS session tickets
//     (OpenSSL's and Node's ticket callbacks); they carry no fips=yes.
//   - TLS 1.2: tls12.go. RSA key exchange and CBC record mode are not served.
//   - X.509 parsing stays in OpenSSL core+base provider (no crypto ops).

// #include <stdlib.h>
// #include <openssl/core_dispatch.h>
// #include <openssl/core_names.h>
// #include <openssl/params.h>
//
// extern int gofips_call_param_cb(OSSL_CALLBACK* cb, void* cbarg, const OSSL_PARAM params[]);
// extern int gofips_build_ec_export_params(OSSL_PARAM out[], const char* group, const unsigned char* pub, size_t publen, const unsigned char* priv, size_t privlen);
// extern const OSSL_PARAM gofips_ec_import_types[4];
// extern const OSSL_PARAM gofips_ec_export_types[3];
// extern const OSSL_PARAM gofips_ec_keymgmt_params[6];
// extern const OSSL_PARAM gofips_mac_settable_ctx_params_tbl[4];
// extern const OSSL_PARAM gofips_kdf_settable_ctx_params_tbl[9];
// extern const OSSL_PARAM gofips_kdf_gettable_ctx_params_tbl[2];
import "C"

import (
	cryptoc "crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/hmac"
	cryptorand "crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha3"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"hash"
	"maps"
	"math/big"
	"sync"
	"unsafe"
)

// ---- context registry helper ----

type regBucket struct {
	mu      sync.Mutex
	nextID  uint64
	entries map[uint64]interface{}
}

var regShared = &regBucket{nextID: 1, entries: map[uint64]interface{}{}}

func regPut(v interface{}) uint64 {
	regShared.mu.Lock()
	defer regShared.mu.Unlock()
	id := regShared.nextID
	regShared.nextID++
	regShared.entries[id] = v
	return id
}

func regGet(id uint64) interface{} {
	regShared.mu.Lock()
	defer regShared.mu.Unlock()
	return regShared.entries[id]
}

func regDel(id uint64) {
	regShared.mu.Lock()
	defer regShared.mu.Unlock()
	delete(regShared.entries, id)
}

// ---- typed, nil-safe registry accessors ----
// (regGet returns interface{}; a missing id yields nil, and a direct type
// assertion `nil.(*T)` panics. Every accessor below asserts only when the
// entry exists.)

func regGetSha384(id uint64) *sha384Ctx {
	v := regGet(id)
	if v == nil {
		return nil
	}
	r, _ := v.(*sha384Ctx)
	return r
}

func regGetSha512(id uint64) *sha512Ctx {
	v := regGet(id)
	if v == nil {
		return nil
	}
	r, _ := v.(*sha512Ctx)
	return r
}

func regGetHmac(id uint64) *hmacCtx {
	v := regGet(id)
	if v == nil {
		return nil
	}
	r, _ := v.(*hmacCtx)
	return r
}

func regGetHkdf(id uint64) *hkdfCtx {
	v := regGet(id)
	if v == nil {
		return nil
	}
	r, _ := v.(*hkdfCtx)
	return r
}

func regGetGcm(id uint64) *gcmCtx {
	v := regGet(id)
	if v == nil {
		return nil
	}
	r, _ := v.(*gcmCtx)
	return r
}

func regGetEcKey(id uint64) *ecKey {
	v := regGet(id)
	if v == nil {
		return nil
	}
	k, _ := v.(*ecKey)
	return k
}

func regGetEcdh(id uint64) *ecdhCtx {
	v := regGet(id)
	if v == nil {
		return nil
	}
	r, _ := v.(*ecdhCtx)
	return r
}

func regGetSha1(id uint64) *sha1Ctx {
	v := regGet(id)
	if v == nil {
		return nil
	}
	r, _ := v.(*sha1Ctx)
	return r
}

func regGetTLS13KDF(id uint64) *tls13kdfCtx {
	v := regGet(id)
	if v == nil {
		return nil
	}
	r, _ := v.(*tls13kdfCtx)
	return r
}

func regGetSig(id uint64) *sigCtx {
	v := regGet(id)
	if v == nil {
		return nil
	}
	r, _ := v.(*sigCtx)
	return r
}

// hashClone duplicates a mid-stream hash state via
// encoding.BinaryMarshaler/Unmarshaler. The digest types are unexported, so
// the fresh destination is selected by (size, blocksize), unambiguous for
// the registered set (sha1 20/64, sha256 32/64, sha384 48/128, sha512 64/128).
func hashClone(src hash.Hash) hash.Hash {
	m, ok := src.(interface{ MarshalBinary() ([]byte, error) })
	if !ok {
		return nil
	}
	state, err := m.MarshalBinary()
	if err != nil {
		return nil
	}
	var dst hash.Hash
	switch {
	case src.Size() == 20 && src.BlockSize() == 64:
		dst = sha1.New()
	case src.Size() == 32 && src.BlockSize() == 64:
		dst = sha256.New()
	case src.Size() == 48 && src.BlockSize() == 128:
		dst = sha512.New384()
	case src.Size() == 64 && src.BlockSize() == 128:
		dst = sha512.New()
	case src.Size() == 28 && src.BlockSize() == 144:
		dst = sha3.New224()
	case src.Size() == 32 && src.BlockSize() == 136:
		dst = sha3.New256()
	case src.Size() == 48 && src.BlockSize() == 104:
		dst = sha3.New384()
	case src.Size() == 64 && src.BlockSize() == 72:
		dst = sha3.New512()
	default:
		return nil
	}
	u, ok := dst.(interface{ UnmarshalBinary([]byte) error })
	if !ok {
		return nil
	}
	if err := u.UnmarshalBinary(state); err != nil {
		return nil
	}
	return dst
}

// gofips_digest_dupctx, SHA-256 dupctx (the sha256 registry lives in
// provider.go: ctxGet/ctxNewWith). Required by EVP_MD_CTX_copy_ex, the
// TLS 1.3 transcript-hash path copies the digest context.
//
//export gofips_digest_dupctx
func gofips_digest_dupctx(src C.uint64_t) C.uint64_t {
	return handleGuard(func() C.uint64_t {
		s := ctxGet(uint64(src))
		if s == nil {
			return 0
		}
		// The registry's narrow Write/Sum interface is implemented by the same
		// concrete digest, which also implements hash.Hash, recover it.
		var clone hash.Hash
		withLock(&s.mu, func() {
			if hh, ok := s.h.(hash.Hash); ok {
				clone = hashClone(hh)
			}
		})
		if clone == nil {
			return 0
		}
		return C.uint64_t(ctxNewWith(clone))
	})
}

// ---- SHA-1 digest op (OSSL_OP_DIGEST) ----
// Node's tls.Server derives its default sessionIdContext with SHA-1. The Go
// module has no SHA-1, so crypto/sha1 runs outside it: the algorithm is
// registered fips=no, for non-security identifiers, and no MAC, KDF or
// signature accepts it (dispatch.c, audit page 03).

type sha1Ctx struct {
	mu sync.Mutex
	h  hash.Hash
}

//export gofips_digest1_newctx
func gofips_digest1_newctx(provctx *C.void) C.uint64_t {
	return handleGuard(func() C.uint64_t {
		_ = provctx
		// No hash is built here: sha1.New() panics under GODEBUG=fips140=only,
		// and this export returns a handle, so it is outside opGuard. The
		// hash is created at init (which IS guarded); update and final refuse
		// a ctx that was never successfully initialised.
		return C.uint64_t(regPut(&sha1Ctx{}))
	})
}

//export gofips_digest1_init
func gofips_digest1_init(dctx C.uint64_t, params *C.OSSL_PARAM) C.int {
	return opGuard(func() C.int { return digest1_initOp(dctx, params) })
}

func digest1_initOp(dctx C.uint64_t, params *C.OSSL_PARAM) C.int {
	_ = params
	ctx := regGetSha1(uint64(dctx))
	if ctx == nil {
		return 0
	}
	// Build and probe the hash before taking the lock. Under
	// GODEBUG=fips140=only Go refuses SHA-1 with a panic, but only when
	// the hash is first used (New succeeds). Sum on the empty state forces
	// that refusal here, so strict mode fails cleanly at init, with no
	// lock held (opGuard recovers the panic, not a mutex).
	h := sha1.New()
	_ = h.Sum(nil)
	withLock(&ctx.mu, func() {
		ctx.h = h
	})
	return 1
}

//export gofips_digest1_update
func gofips_digest1_update(dctx C.uint64_t, in *C.uchar, inl C.size_t) C.int {
	return opGuard(func() C.int { return digest1Update(dctx, in, inl) })
}

func digest1Update(dctx C.uint64_t, in *C.uchar, inl C.size_t) C.int {
	ctx := regGetSha1(uint64(dctx))
	if ctx == nil || (in == nil && inl > 0) {
		return 0
	}
	if ctx.h == nil {
		return 0 // no successful init: refuse (no nil-hash write)
	}
	b := unsafe.Slice((*byte)(unsafe.Pointer(in)), int(inl))
	ctx.mu.Lock()
	defer ctx.mu.Unlock() // deferred: a panic in the hash must not leave the lock held
	_, _ = ctx.h.Write(b)
	return 1
}

//export gofips_digest1_final
func gofips_digest1_final(dctx C.uint64_t, out *C.uchar, outl *C.size_t, outsz C.size_t) C.int {
	return opGuard(func() C.int { return digest1Final(dctx, out, outl, outsz) })
}

func digest1Final(dctx C.uint64_t, out *C.uchar, outl *C.size_t, outsz C.size_t) C.int {
	ctx := regGetSha1(uint64(dctx))
	if ctx == nil || out == nil || outl == nil || outsz < 20 {
		return 0
	}
	sum := func() []byte {
		ctx.mu.Lock()
		defer ctx.mu.Unlock() // deferred: a panic in the hash must not leave the lock held
		if ctx.h == nil {
			return nil // no successful init: refuse
		}
		return ctx.h.Sum(nil)
	}()
	if len(sum) != 20 {
		return 0
	}
	copy(unsafe.Slice((*byte)(unsafe.Pointer(out)), 20), sum)
	*outl = 20
	recordOp("digest")
	return 1
}

//export gofips_digest1_dupctx
func gofips_digest1_dupctx(src C.uint64_t) C.uint64_t {
	return handleGuard(func() C.uint64_t {
		s := regGetSha1(uint64(src))
		if s == nil {
			return 0
		}
		var clone hash.Hash
		withLock(&s.mu, func() { clone = hashClone(s.h) })
		if clone == nil {
			return 0
		}
		return C.uint64_t(regPut(&sha1Ctx{h: clone}))
	})
}

//export gofips_digest1_freectx
func gofips_digest1_freectx(dctx C.uint64_t) {
	if ctx := regGetSha1(uint64(dctx)); ctx != nil {
		withLock(&ctx.mu, func() {
			ctx.h = nil
		})
	}
	regDel(uint64(dctx))
}

//export gofips_digest1_get_params
func gofips_digest1_get_params(params *C.OSSL_PARAM) C.int {
	return opGuard(func() C.int { return digest1_get_paramsOp(params) })
}

func digest1_get_paramsOp(params *C.OSSL_PARAM) C.int {
	return digestParams(params, 20, 64)
}

//export gofips_digest1_get_ctx_params
func gofips_digest1_get_ctx_params(dctx C.uint64_t, params *C.OSSL_PARAM) C.int {
	return opGuard(func() C.int { return digest1_get_ctx_paramsOp(dctx, params) })
}

func digest1_get_ctx_paramsOp(dctx C.uint64_t, params *C.OSSL_PARAM) C.int {
	_ = dctx
	return digestParams(params, 20, 64)
}

//export gofips_digest1_set_ctx_params
func gofips_digest1_set_ctx_params(dctx C.uint64_t, params *C.OSSL_PARAM) C.int {
	return opGuard(func() C.int { return digest1_set_ctx_paramsOp(dctx, params) })
}

func digest1_set_ctx_paramsOp(dctx C.uint64_t, params *C.OSSL_PARAM) C.int {
	_ = dctx
	_ = params
	return 0
}

//export gofips_digest1_gettable_ctx_params
func gofips_digest1_gettable_ctx_params(dctx C.uint64_t, params *C.OSSL_PARAM) *C.OSSL_PARAM {
	_ = dctx
	_ = params
	return nil
}

//export gofips_digest1_settable_ctx_params
func gofips_digest1_settable_ctx_params(dctx, provctx unsafe.Pointer) *C.OSSL_PARAM {
	_, _ = dctx, provctx
	return nil // no settable parameters
}

// ---- SHA-384 digest op (OSSL_OP_DIGEST) ----

type sha384Ctx struct {
	mu sync.Mutex
	h  hash.Hash
}

//export gofips_digest384_newctx
func gofips_digest384_newctx(provctx *C.void) C.uint64_t {
	return handleGuard(func() C.uint64_t {
		_ = provctx
		return C.uint64_t(regPut(&sha384Ctx{h: sha512.New384()}))
	})
}

//export gofips_digest384_init
func gofips_digest384_init(dctx C.uint64_t, params *C.OSSL_PARAM) C.int {
	return opGuard(func() C.int { return digest384_initOp(dctx, params) })
}

func digest384_initOp(dctx C.uint64_t, params *C.OSSL_PARAM) C.int {
	_ = params
	ctx := regGetSha384(uint64(dctx))
	if ctx == nil {
		return 0
	}
	withLock(&ctx.mu, func() {
		ctx.h = sha512.New384()
	})
	return 1
}

//export gofips_digest384_update
func gofips_digest384_update(dctx C.uint64_t, in *C.uchar, inl C.size_t) C.int {
	return opGuard(func() C.int { return digest384Update(dctx, in, inl) })
}

func digest384Update(dctx C.uint64_t, in *C.uchar, inl C.size_t) C.int {
	dbg("digest384_update id=%d inl=%d", int64(dctx), int(inl))
	ctx := regGetSha384(uint64(dctx))
	if ctx == nil || (in == nil && inl > 0) {
		return 0
	}
	b := unsafe.Slice((*byte)(unsafe.Pointer(in)), int(inl))
	if debugEnabled && len(b) >= 4 {
		head := b
		if len(head) > 8 {
			head = head[:8]
		}
		chunkSum := sha256.Sum256(b)
		if inl <= 700 {
			dbg("digest384_update FULL id=%d inl=%d data=%x sum=%x", int64(dctx), int(inl), b, chunkSum[:8])
		} else {
			dbg("digest384_update id=%d inl=%d head=%x tail=%x chunksum=%x", int64(dctx), int(inl), head, b[len(b)-4:], chunkSum[:8])
		}
	}
	withLock(&ctx.mu, func() { _, _ = ctx.h.Write(b) })
	return 1
}

//export gofips_digest384_final
func gofips_digest384_final(dctx C.uint64_t, out *C.uchar, outl *C.size_t, outsz C.size_t) C.int {
	return opGuard(func() C.int { return digest384Final(dctx, out, outl, outsz) })
}

func digest384Final(dctx C.uint64_t, out *C.uchar, outl *C.size_t, outsz C.size_t) C.int {
	ctx := regGetSha384(uint64(dctx))
	if ctx == nil || out == nil || outl == nil || outsz < 48 {
		return 0
	}
	var sum []byte
	withLock(&ctx.mu, func() { sum = ctx.h.Sum(nil) })
	if len(sum) != 48 {
		return 0
	}
	if debugEnabled {
		dbg("digest384_final id=%d sum=%x", int64(dctx), sum)
	}
	copy(unsafe.Slice((*byte)(unsafe.Pointer(out)), 48), sum)
	*outl = 48
	recordOp("digest")
	return 1
}

//export gofips_digest384_dupctx
func gofips_digest384_dupctx(src C.uint64_t) C.uint64_t {
	return handleGuard(func() C.uint64_t {
		dbg("digest384_dupctx src=%d", int64(src))
		s := regGetSha384(uint64(src))
		if s == nil {
			dbg("digest384_dupctx: nil src")
			return 0
		}
		var clone hash.Hash
		withLock(&s.mu, func() { clone = hashClone(s.h) })
		if clone == nil {
			dbg("digest384_dupctx: clone failed")
			return 0
		}
		return C.uint64_t(regPut(&sha384Ctx{h: clone}))
	})
}

//export gofips_digest384_freectx
func gofips_digest384_freectx(dctx C.uint64_t) {
	if ctx := regGetSha384(uint64(dctx)); ctx != nil {
		withLock(&ctx.mu, func() {
			ctx.h = nil
		})
	}
	regDel(uint64(dctx))
}

//export gofips_digest384_get_params
func gofips_digest384_get_params(params *C.OSSL_PARAM) C.int {
	return opGuard(func() C.int { return digest384_get_paramsOp(params) })
}

func digest384_get_paramsOp(params *C.OSSL_PARAM) C.int {
	return digestParams(params, 48, 128)
}

//export gofips_digest384_get_ctx_params
func gofips_digest384_get_ctx_params(dctx C.uint64_t, params *C.OSSL_PARAM) C.int {
	return opGuard(func() C.int { return digest384_get_ctx_paramsOp(dctx, params) })
}

func digest384_get_ctx_paramsOp(dctx C.uint64_t, params *C.OSSL_PARAM) C.int {
	_ = dctx
	return digestParams(params, 48, 128)
}

//export gofips_digest384_set_ctx_params
func gofips_digest384_set_ctx_params(dctx C.uint64_t, params *C.OSSL_PARAM) C.int {
	return opGuard(func() C.int { return digest384_set_ctx_paramsOp(dctx, params) })
}

func digest384_set_ctx_paramsOp(dctx C.uint64_t, params *C.OSSL_PARAM) C.int {
	_ = dctx
	_ = params
	return 0 // fail closed
}

//export gofips_digest384_gettable_ctx_params
func gofips_digest384_gettable_ctx_params(dctx C.uint64_t, params *C.OSSL_PARAM) *C.OSSL_PARAM {
	_ = dctx
	_ = params
	return nil
}

//export gofips_digest384_settable_ctx_params
func gofips_digest384_settable_ctx_params(dctx, provctx unsafe.Pointer) *C.OSSL_PARAM {
	_, _ = dctx, provctx
	return nil // no settable parameters
}

// ---- SHA-512 digest op (OSSL_OP_DIGEST) ----
// Same shape as SHA-384; registered as SHA2-512 (dispatch.c), backed by
// crypto/sha512, the module's Message Digest SHA2-512 service (page 03).

type sha512Ctx struct {
	mu sync.Mutex
	h  hash.Hash
}

//export gofips_digest512_newctx
func gofips_digest512_newctx(provctx *C.void) C.uint64_t {
	return handleGuard(func() C.uint64_t {
		_ = provctx
		return C.uint64_t(regPut(&sha512Ctx{h: sha512.New()}))
	})
}

//export gofips_digest512_init
func gofips_digest512_init(dctx C.uint64_t, params *C.OSSL_PARAM) C.int {
	return opGuard(func() C.int { return digest512_initOp(dctx, params) })
}

func digest512_initOp(dctx C.uint64_t, params *C.OSSL_PARAM) C.int {
	_ = params
	ctx := regGetSha512(uint64(dctx))
	if ctx == nil {
		return 0
	}
	withLock(&ctx.mu, func() {
		ctx.h = sha512.New()
	})
	return 1
}

//export gofips_digest512_update
func gofips_digest512_update(dctx C.uint64_t, in *C.uchar, inl C.size_t) C.int {
	return opGuard(func() C.int { return digest512Update(dctx, in, inl) })
}

func digest512Update(dctx C.uint64_t, in *C.uchar, inl C.size_t) C.int {
	ctx := regGetSha512(uint64(dctx))
	if ctx == nil || (in == nil && inl > 0) {
		return 0
	}
	if ctx.h == nil {
		return 0 // no successful init: refuse (no nil-hash write)
	}
	b := unsafe.Slice((*byte)(unsafe.Pointer(in)), int(inl))
	withLock(&ctx.mu, func() { _, _ = ctx.h.Write(b) })
	return 1
}

//export gofips_digest512_final
func gofips_digest512_final(dctx C.uint64_t, out *C.uchar, outl *C.size_t, outsz C.size_t) C.int {
	return opGuard(func() C.int { return digest512Final(dctx, out, outl, outsz) })
}

func digest512Final(dctx C.uint64_t, out *C.uchar, outl *C.size_t, outsz C.size_t) C.int {
	ctx := regGetSha512(uint64(dctx))
	if ctx == nil || out == nil || outl == nil || outsz < 64 {
		return 0
	}
	var sum []byte
	withLock(&ctx.mu, func() { sum = ctx.h.Sum(nil) })
	if len(sum) != 64 {
		return 0
	}
	copy(unsafe.Slice((*byte)(unsafe.Pointer(out)), 64), sum)
	*outl = 64
	recordOp("digest")
	return 1
}

//export gofips_digest512_dupctx
func gofips_digest512_dupctx(src C.uint64_t) C.uint64_t {
	return handleGuard(func() C.uint64_t {
		s := regGetSha512(uint64(src))
		if s == nil {
			return 0
		}
		var clone hash.Hash
		withLock(&s.mu, func() { clone = hashClone(s.h) })
		if clone == nil {
			return 0
		}
		return C.uint64_t(regPut(&sha512Ctx{h: clone}))
	})
}

//export gofips_digest512_freectx
func gofips_digest512_freectx(dctx C.uint64_t) {
	if ctx := regGetSha512(uint64(dctx)); ctx != nil {
		withLock(&ctx.mu, func() {
			ctx.h = nil
		})
	}
	regDel(uint64(dctx))
}

//export gofips_digest512_get_params
func gofips_digest512_get_params(params *C.OSSL_PARAM) C.int {
	return opGuard(func() C.int { return digest512_get_paramsOp(params) })
}

func digest512_get_paramsOp(params *C.OSSL_PARAM) C.int {
	return digestParams(params, 64, 128)
}

//export gofips_digest512_get_ctx_params
func gofips_digest512_get_ctx_params(dctx C.uint64_t, params *C.OSSL_PARAM) C.int {
	return opGuard(func() C.int { return digest512_get_ctx_paramsOp(dctx, params) })
}

func digest512_get_ctx_paramsOp(dctx C.uint64_t, params *C.OSSL_PARAM) C.int {
	_ = dctx
	return digestParams(params, 64, 128)
}

//export gofips_digest512_set_ctx_params
func gofips_digest512_set_ctx_params(dctx C.uint64_t, params *C.OSSL_PARAM) C.int {
	return opGuard(func() C.int { return digest512_set_ctx_paramsOp(dctx, params) })
}

func digest512_set_ctx_paramsOp(dctx C.uint64_t, params *C.OSSL_PARAM) C.int {
	_ = dctx
	_ = params
	return 0
}

//export gofips_digest512_gettable_ctx_params
func gofips_digest512_gettable_ctx_params(dctx C.uint64_t, params *C.OSSL_PARAM) *C.OSSL_PARAM {
	_ = dctx
	_ = params
	return nil
}

//export gofips_digest512_settable_ctx_params
func gofips_digest512_settable_ctx_params(dctx, provctx unsafe.Pointer) *C.OSSL_PARAM {
	_, _ = dctx, provctx
	return nil // no settable parameters
}

func digestParams(params *C.OSSL_PARAM, size, blocksize uint64) C.int {
	if params == nil {
		return 0
	}
	ok := 1
	for i := 0; i < paramCount(params); i++ {
		p := paramAt(params, i)
		if p.key == nil {
			break
		}
		switch C.GoString(p.key) {
		case C.OSSL_DIGEST_PARAM_SIZE:
			if !setUint(p, size) {
				ok = 0
			}
		case C.OSSL_DIGEST_PARAM_BLOCK_SIZE:
			if !setUint(p, blocksize) {
				ok = 0
			}
		}
	}
	return C.int(ok)
}

// ---- HMAC (OSSL_OP_MAC) ----

type hmacCtx struct {
	mu     sync.Mutex
	h      hash.Hash
	key    []byte
	digest cryptoc.Hash // for the next keying; a digest set takes effect then
	hDig   cryptoc.Hash // the digest h was keyed with
	writes int          // streaming updates since init: >0 means mid-stream (not cloneable)
}

// rekey keys h with the current digest and key. Callers hold mu.
func (c *hmacCtx) rekey() {
	d := c.digest
	c.h = hmac.New(func() hash.Hash { return hmacHashNew(d) }, c.key)
	c.hDig, c.writes = d, 0
}

func hmacHashNew(h cryptoc.Hash) hash.Hash {
	switch h {
	case cryptoc.SHA256:
		return sha256.New()
	case cryptoc.SHA384:
		return sha512.New384()
	case cryptoc.SHA512:
		return sha512.New()
	case cryptoc.SHA3_224:
		return sha3.New224()
	case cryptoc.SHA3_256:
		return sha3.New256()
	case cryptoc.SHA3_384:
		return sha3.New384()
	case cryptoc.SHA3_512:
		return sha3.New512()
	}
	return nil
}

func hmacHashFromName(name string) cryptoc.Hash {
	fn, ok := approvedDigest(name)
	if !ok {
		return 0 // fail closed
	}
	switch h := fn(); {
	case h.Size() == 32 && h.BlockSize() == 64:
		return cryptoc.SHA256
	case h.Size() == 48 && h.BlockSize() == 128:
		return cryptoc.SHA384
	case h.Size() == 64 && h.BlockSize() == 128:
		return cryptoc.SHA512
	case h.Size() == 28 && h.BlockSize() == 144:
		return cryptoc.SHA3_224
	case h.Size() == 32 && h.BlockSize() == 136:
		return cryptoc.SHA3_256
	case h.Size() == 48 && h.BlockSize() == 104:
		return cryptoc.SHA3_384
	case h.Size() == 64 && h.BlockSize() == 72:
		return cryptoc.SHA3_512
	}
	return 0
}

//export gofips_mac_newctx
func gofips_mac_newctx(provctx *C.void) C.uint64_t {
	return handleGuard(func() C.uint64_t {
		dbg("mac_newctx")
		_ = provctx
		return C.uint64_t(regPut(&hmacCtx{}))
	})
}

//export gofips_mac_dupctx
func gofips_mac_dupctx(src C.uint64_t) C.uint64_t {
	return handleGuard(func() C.uint64_t {
		dbg("mac_dupctx")
		s := regGetHmac(uint64(src))
		if s == nil {
			return 0
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		// Dup of a mid-stream HMAC: Go's public hash.Hash API cannot clone
		// streaming state (Sum does not expose the state), so a key-only
		// clone would silently drop the prior updates.
		// A ctx with no writes is safely cloneable: hmac.New with the same
		// key reproduces the identical fresh state. The writes counter
		// distinguishes the two (a hash with writes cannot be distinguished
		// from a fresh one via the public API alone).
		if s.h != nil && s.writes > 0 {
			dbg("mac_dupctx REFUSED: mid-stream HMAC state is not cloneable via the public Go API")
			return 0
		}
		n := &hmacCtx{digest: s.digest, hDig: s.hDig, key: append([]byte(nil), s.key...)}
		if s.h != nil {
			if hmacHashNew(s.hDig) == nil {
				return 0
			}
			// Fresh-but-initialized ctx: the dup carries the keyed HMAC
			// state, not a plain digest. hmac.New with the stored key yields
			// the identical fresh keyed state the original had.
			d := s.hDig
			n.h = hmac.New(func() hash.Hash { return hmacHashNew(d) }, n.key)
		}
		return C.uint64_t(regPut(n))
	})
}

//export gofips_mac_freectx
func gofips_mac_freectx(mctx C.uint64_t) {
	if ctx := regGetHmac(uint64(mctx)); ctx != nil {
		withLock(&ctx.mu, func() { clear(ctx.key); ctx.key, ctx.h = nil, nil })
	}
	regDel(uint64(mctx))
}

//export gofips_mac_init
func gofips_mac_init(mctx C.uint64_t, key *C.uchar, keylen C.size_t, params *C.OSSL_PARAM) C.int {
	return opGuard(func() C.int { return macInit(mctx, key, keylen, params) })
}

func macInit(mctx C.uint64_t, key *C.uchar, keylen C.size_t, params *C.OSSL_PARAM) C.int {
	dbg("mac_init keylen=%d params=%v", int(keylen), params != nil)
	ctx := regGetHmac(uint64(mctx))
	if ctx == nil || (key == nil && keylen > 0) {
		return 0
	}
	// HMAC keys of at least 112 bits (IG C.B, SP 800-131A Rev.2); shorter
	// and empty keys are refused, not padded.
	minKey := 14 // 112 bits
	var newKey []byte
	if key != nil && keylen > 0 {
		kb := unsafe.Slice((*byte)(unsafe.Pointer(key)), int(keylen))
		if len(kb) < minKey {
			dbg("mac_init REFUSED: keylen=%d < %d for the selected digest", int(keylen), minKey)
			return 0
		}
		newKey = append([]byte(nil), kb...)
	} else { // NULL-key: params may carry the key; else reuse the stored key
		// NULL-key init: EVP_MAC_init(ctx, NULL, 0, params) re-inits
		// with the ctx's stored key (EVP semantics). A key may also
		// arrive via params (set_ctx_params path). No key anywhere =
		// refuse.
		if params != nil {
			for i := 0; i < paramCount(params); i++ {
				p := paramAt(params, i)
				if p.key == nil {
					break
				}
				if C.GoString(p.key) == C.OSSL_MAC_PARAM_KEY {
					newKey = append([]byte(nil), getOctetParam(p)...)
				}
			}
		}
		if len(newKey) == 0 {
			ctx.mu.Lock()
			reuse := ctx.key
			ctx.mu.Unlock()
			if len(reuse) >= minKey {
				newKey = reuse
			} else {
				dbg("mac_init REFUSED: NULL-key init with no stored key (or shorter than %d)", minKey)
				return 0
			}
		}
		if len(newKey) < minKey {
			dbg("mac_init REFUSED: keylen=%d < %d", len(newKey), minKey)
			return 0
		}
	}
	if params != nil {
		for i := 0; i < paramCount(params); i++ {
			p := paramAt(params, i)
			if p.key == nil {
				break
			}
			switch C.GoString(p.key) {
			case C.OSSL_MAC_PARAM_DIGEST:
				var dn string
				if !getUtf8Param(p, &dn) {
					return 0
				}
				ctx.digest = hmacHashFromName(dn)
			}
		}
	}
	h := hmacHashNew(ctx.digest)
	if h == nil {
		return 0 // fail closed: unregistered/missing digest
	}
	withLock(&ctx.mu, func() {
		ctx.key = append([]byte(nil), newKey...)
		ctx.rekey()
	})
	return 1
}

//export gofips_mac_update
func gofips_mac_update(mctx C.uint64_t, in *C.uchar, inl C.size_t) C.int {
	return opGuard(func() C.int { return macUpdate(mctx, in, inl) })
}

func macUpdate(mctx C.uint64_t, in *C.uchar, inl C.size_t) C.int {
	dbg("mac_update inl=%d", int(inl))
	ctx := regGetHmac(uint64(mctx))
	if ctx == nil || (in == nil && inl > 0) {
		return 0
	}
	if ctx.h == nil {
		return 0 // no successful init: refuse (no nil-hash write)
	}
	b := unsafe.Slice((*byte)(unsafe.Pointer(in)), int(inl))
	withLock(&ctx.mu, func() {
		_, _ = ctx.h.Write(b)
		ctx.writes++
	})
	return 1
}

//export gofips_mac_final
func gofips_mac_final(mctx C.uint64_t, out *C.uchar, outl *C.size_t, outsz C.size_t) C.int {
	return opGuard(func() C.int { return macFinal(mctx, out, outl, outsz) })
}

func macFinal(mctx C.uint64_t, out *C.uchar, outl *C.size_t, outsz C.size_t) C.int {
	dbg("mac_final outsz=%d", int(outsz))
	ctx := regGetHmac(uint64(mctx))
	if ctx == nil || out == nil || outl == nil {
		return 0
	}
	var sum []byte
	inited := false
	withLock(&ctx.mu, func() {
		if ctx.h != nil {
			inited = true
			sum = ctx.h.Sum(nil)
		}
	})
	if !inited {
		return 0 // no successful init: refuse (no nil-hash finalize)
	}
	if len(sum) > int(outsz) {
		return 0
	}
	copy(unsafe.Slice((*byte)(unsafe.Pointer(out)), len(sum)), sum)
	*outl = C.size_t(len(sum))
	recordOp("mac")
	return 1
}

//export gofips_mac_get_params
func gofips_mac_get_params(params *C.OSSL_PARAM) C.int {
	return opGuard(func() C.int { return mac_get_paramsOp(params) })
}

func mac_get_paramsOp(params *C.OSSL_PARAM) C.int {
	_ = params
	return 1
}

//export gofips_mac_get_ctx_params
func gofips_mac_get_ctx_params(mctx C.uint64_t, params *C.OSSL_PARAM) C.int {
	return opGuard(func() C.int { return mac_get_ctx_paramsOp(mctx, params) })
}

func mac_get_ctx_paramsOp(mctx C.uint64_t, params *C.OSSL_PARAM) C.int {
	ctx := regGetHmac(uint64(mctx))
	if ctx == nil {
		return 0
	}
	if params == nil {
		return 1
	}
	ok := 1
	for i := 0; i < paramCount(params); i++ {
		p := paramAt(params, i)
		if p.key == nil {
			break
		}
		switch C.GoString(p.key) {
		case C.OSSL_MAC_PARAM_SIZE:
			ctx.mu.Lock()
			if ctx.h == nil {
				ctx.mu.Unlock()
				return 0 // no successful init: no size to report
			}
			sz := ctx.h.Size()
			ctx.mu.Unlock()
			if !setUint(p, uint64(sz)) {
				ok = 0
			}
		}
	}
	return C.int(ok)
}

//export gofips_mac_set_ctx_params
func gofips_mac_set_ctx_params(mctx C.uint64_t, params *C.OSSL_PARAM) C.int {
	return opGuard(func() C.int { return mac_set_ctx_paramsOp(mctx, params) })
}

func mac_set_ctx_paramsOp(mctx C.uint64_t, params *C.OSSL_PARAM) C.int {
	ctx := regGetHmac(uint64(mctx))
	if ctx == nil {
		return 0
	}
	if params == nil {
		return 1 // nothing to set
	}
	ok := 1
	for i := 0; i < paramCount(params); i++ {
		p := paramAt(params, i)
		if p.key == nil {
			break
		}
		switch C.GoString(p.key) {
		case C.OSSL_MAC_PARAM_DIGEST:
			var dn string
			if !getUtf8Param(p, &dn) {
				return 0
			}
			// A refused name leaves the digest as it was.
			d := hmacHashFromName(dn)
			if d == 0 {
				return 0
			}
			withLock(&ctx.mu, func() { ctx.digest = d })
		case C.OSSL_MAC_PARAM_KEY:
			// As the default provider: a key set re-keys the MAC now (and
			// is kept for a later key-less init), under the same 112-bit
			// floor as init.
			key := getOctetParam(p)
			if len(key) < 14 {
				return 0
			}
			withLock(&ctx.mu, func() {
				ctx.key = append([]byte(nil), key...)
				if ctx.h != nil && hmacHashNew(ctx.digest) != nil {
					ctx.rekey()
				}
			})
		}
	}
	return C.int(ok)
}

//export gofips_mac_gettable_params
func gofips_mac_gettable_params(provctx *C.void) *C.OSSL_PARAM {
	_ = provctx
	return nil
}

//export gofips_mac_gettable_ctx_params
func gofips_mac_gettable_ctx_params(mctx C.uint64_t, provctx *C.void) *C.OSSL_PARAM {
	_ = mctx
	_ = provctx
	return nil
}

//export gofips_mac_settable_ctx_params
func gofips_mac_settable_ctx_params(mctx C.uint64_t, provctx *C.void) *C.OSSL_PARAM {
	_ = mctx
	_ = provctx
	// EVP_Q_mac checks settable_ctx_params for 'digest' before use,
	// returning NULL makes every one-shot HMAC fail 'invalid argument'.
	return (*C.OSSL_PARAM)(unsafe.Pointer(&C.gofips_mac_settable_ctx_params_tbl[0]))
}

// ---- HKDF (OSSL_OP_KDF) ----

type hkdfCtx struct {
	mu      sync.Mutex
	hashFn  func() hash.Hash
	salt    []byte
	key     []byte
	info    [][]byte
	mode    int // 0 unset => extract-and-expand; 1 EXTRACT_ONLY; 2 EXPAND_ONLY
	modeSet bool
}

//export gofips_kdf_newctx
func gofips_kdf_newctx(provctx *C.void) C.uint64_t {
	return handleGuard(func() C.uint64_t {
		dbg("kdf_newctx")
		_ = provctx
		return C.uint64_t(regPut(&hkdfCtx{hashFn: sha256.New}))
	})
}

//export gofips_kdf_freectx
func gofips_kdf_freectx(kctx C.uint64_t) {
	if ctx := regGetHkdf(uint64(kctx)); ctx != nil {
		withLock(&ctx.mu, func() { clear(ctx.key); ctx.key = nil })
	}
	regDel(uint64(kctx))
}

//export gofips_kdf_reset
func gofips_kdf_reset(kctx C.uint64_t) {
	ctx := regGetHkdf(uint64(kctx))
	if ctx == nil {
		return
	}
	withLock(&ctx.mu, func() {
		ctx.salt, ctx.key, ctx.info = nil, nil, nil
		ctx.mode, ctx.modeSet = 0, false
	})
}

//export gofips_kdf_derive
func gofips_kdf_derive(kctx C.uint64_t, key *C.uchar, keylen C.size_t, params *C.OSSL_PARAM) C.int {
	return opGuard(func() C.int { return kdfDerive(kctx, key, keylen, params) })
}

func kdfDerive(kctx C.uint64_t, key *C.uchar, keylen C.size_t, params *C.OSSL_PARAM) C.int {
	dbg("kdf_derive keylen=%d", int(keylen))
	ctx := regGetHkdf(uint64(kctx))
	if ctx == nil || key == nil || keylen == 0 {
		return 0
	}
	ctx.mu.Lock()
	fn := ctx.hashFn
	salt := append([]byte(nil), ctx.salt...)
	ikm := append([]byte(nil), ctx.key...)
	var info []byte
	for _, i := range ctx.info {
		info = append(info, i...)
	}
	ctx.mu.Unlock()
	// Params passed to derive override or add to the ctx state
	// (EVP_KDF_derive forwards its params argument here).
	explicitMode := 0
	modeSet := false
	if ctx.modeSet {
		explicitMode = ctx.mode
		modeSet = true
	}
	if params != nil {
		for i := 0; i < paramCount(params); i++ {
			p := paramAt(params, i)
			if p.key == nil {
				break
			}
			switch C.GoString(p.key) {
			case C.OSSL_KDF_PARAM_KEY:
				ikm = append([]byte(nil), getOctetParam(p)...)
			case C.OSSL_KDF_PARAM_SALT:
				salt = append([]byte(nil), getOctetParam(p)...)
			case C.OSSL_KDF_PARAM_INFO:
				// Derive-level INFO: replace, not accumulate:
				// same RFC 5869 semantics as set_ctx_params.
				info = append([]byte(nil), getOctetParam(p)...)
			case C.OSSL_KDF_PARAM_MODE:
				m, ok := kdfMode(p)
				if !ok {
					return 0
				}
				explicitMode, modeSet = m, true
			case C.OSSL_KDF_PARAM_DIGEST:
				var dn string
				if !getUtf8Param(p, &dn) {
					return 0
				}
				f, ok := approvedDigest(dn)
				if !ok {
					dbg("kdf_derive REFUSED: unregistered digest %q", dn)
					return 0
				}
				fn = f
			}
		}
	}

	out := unsafe.Slice((*byte)(unsafe.Pointer(key)), int(keylen))
	// RFC 5869 modes:
	//   EXTRACT_ONLY (1): out = PRK = HMAC(salt, ikm), outlen must be
	//     the digest length
	//   EXPAND_ONLY (2): OKM = HKDF-Expand(PRK=key, info, L)
	//   EXTRACT_AND_EXPAND (0, the default): Extract then Expand
	// (EVP_KDF_HKDF_MODE_* in openssl/kdf.h).
	const (
		modeExtractOnly   = 1
		modeExpandOnly    = 2
		modeExtractExpand = 0
	)
	mode := modeExtractExpand
	if modeSet {
		mode = explicitMode
	}
	// RFC 5869 caps OKM at 255*HashLen.
	mdLen := fn().Size()
	if mode != modeExtractOnly && uint64(keylen) > 255*uint64(mdLen) {
		dbg("kdf_derive REFUSED: keylen=%d exceeds HKDF max %d (255*HashLen)", int(keylen), 255*mdLen)
		return 0
	}
	// A KDF secret (IKM) of at least 112 bits (IG C.B, SP 800-131A Rev.2).
	if len(ikm) < 14 {
		dbg("kdf_derive REFUSED: IKM %d bytes < 112-bit SP minimum", len(ikm))
		return 0
	}
	// crypto/hkdf: in FIPS mode, the module's HKDF service.
	switch mode {
	case modeExtractOnly:
		if uint64(keylen) != uint64(mdLen) {
			dbg("kdf_derive REFUSED: EXTRACT_ONLY requires keylen == HashLen (%d), got %d", mdLen, int(keylen))
			return 0
		}
		prk, err := hkdf.Extract(fn, ikm, salt)
		if err != nil {
			dbg("kdf_derive Extract FAILED: %v", err)
			return 0
		}
		copy(out, prk)
	case modeExpandOnly:
		okm, err := hkdf.Expand(fn, ikm, string(info), int(keylen))
		if err != nil {
			dbg("kdf_derive Expand FAILED: %v", err)
			return 0
		}
		copy(out, okm)
	default:
		okm, err := hkdf.Key(fn, ikm, salt, string(info), int(keylen))
		if err != nil {
			dbg("kdf_derive Key FAILED: %v", err)
			return 0
		}
		copy(out, okm)
	}
	recordOp("kdf")
	return 1
}

//export gofips_kdf_set_ctx_params
func gofips_kdf_set_ctx_params(kctx C.uint64_t, params *C.OSSL_PARAM) C.int {
	return opGuard(func() C.int { return kdf_set_ctx_paramsOp(kctx, params) })
}

func kdf_set_ctx_paramsOp(kctx C.uint64_t, params *C.OSSL_PARAM) C.int {
	dbg("kdf_set_ctx_params params=%v", params != nil)
	ctx := regGetHkdf(uint64(kctx))
	if ctx == nil {
		return 0
	}
	ok := 1
	for i := 0; i < paramCount(params); i++ {
		p := paramAt(params, i)
		if p.key == nil {
			break
		}
		switch C.GoString(p.key) {
		case C.OSSL_KDF_PARAM_KEY:
			withLock(&ctx.mu, func() {
				ctx.key = append([]byte(nil), getOctetParam(p)...)
			})
		case C.OSSL_KDF_PARAM_SALT:
			withLock(&ctx.mu, func() {
				ctx.salt = append([]byte(nil), getOctetParam(p)...)
			})
		case C.OSSL_KDF_PARAM_INFO:
			// INFO is replaced, not accumulated, as in the default
			// provider: the RFC 5869 info parameter is a single value.
			withLock(&ctx.mu, func() {
				ctx.info = [][]byte{append([]byte(nil), getOctetParam(p)...)}
			})
		case C.OSSL_KDF_PARAM_MODE:
			if m, good := kdfMode(p); good {
				withLock(&ctx.mu, func() {
					ctx.mode = m
					ctx.modeSet = true
				})
			} else {
				ok = 0
			}
		case C.OSSL_KDF_PARAM_DIGEST:
			var dn string
			if !getUtf8Param(p, &dn) {
				ok = 0
			} else if fn, approved := approvedDigest(dn); approved {
				withLock(&ctx.mu, func() {
					ctx.hashFn = fn
				})
			} else {
				ok = 0
			}
		}
	}
	return C.int(ok)
}

//export gofips_kdf_gettable_ctx_params
func gofips_kdf_gettable_ctx_params(kctx C.uint64_t, provctx *C.void) *C.OSSL_PARAM {
	_ = kctx
	_ = provctx
	// SIZE only, as the default provider's HKDF.
	return (*C.OSSL_PARAM)(unsafe.Pointer(&C.gofips_kdf_gettable_ctx_params_tbl[0]))
}

//export gofips_kdf_settable_ctx_params
func gofips_kdf_settable_ctx_params(kctx C.uint64_t, provctx *C.void) *C.OSSL_PARAM {
	_ = kctx
	_ = provctx
	// EVP_KDF_CTX_set_params validates against this list; nil fails
	// every derive with 'passed invalid argument'.
	return (*C.OSSL_PARAM)(unsafe.Pointer(&C.gofips_kdf_settable_ctx_params_tbl[0]))
}

//export gofips_kdf_get_ctx_params
func gofips_kdf_get_ctx_params(kctx C.uint64_t, params *C.OSSL_PARAM) C.int {
	return opGuard(func() C.int { return kdf_get_ctx_paramsOp(kctx, params) })
}

func kdf_get_ctx_paramsOp(kctx C.uint64_t, params *C.OSSL_PARAM) C.int {
	ctx, _ := regGet(uint64(kctx)).(*hkdfCtx)
	if params == nil || ctx == nil {
		return 0
	}
	ok := 1
	served := 0
	for i := 0; i < paramCount(params); i++ {
		p := paramAt(params, i)
		if p.key == nil {
			break
		}
		switch C.GoString(p.key) {
		case C.OSSL_KDF_PARAM_SIZE:
			// As the default provider: the digest length in extract-only
			// mode (the PRK), otherwise no fixed size (SIZE_MAX); the
			// RFC 5869 bound is enforced at derive.
			size := ^uint64(0)
			withLock(&ctx.mu, func() {
				if ctx.mode == 1 && ctx.hashFn != nil {
					size = uint64(ctx.hashFn().Size())
				}
			})
			if !setUint(p, size) {
				ok = 0
			}
			served++
		default:
			// An unknown GET key fails, as in the default provider.
			ok = 0
		}
	}
	_ = served
	return C.int(ok)
}

//export gofips_kdf_gettable_params
func gofips_kdf_gettable_params(provctx *C.void) *C.OSSL_PARAM {
	_ = provctx
	return nil
}

//export gofips_kdf_get_params
func gofips_kdf_get_params(params *C.OSSL_PARAM) C.int {
	return opGuard(func() C.int { return kdf_get_paramsOp(params) })
}

func kdf_get_paramsOp(params *C.OSSL_PARAM) C.int {
	_ = params
	return 1
}

//export gofips_kdf_dupctx
func gofips_kdf_dupctx(src C.uint64_t) C.uint64_t {
	return handleGuard(func() C.uint64_t {
		s := regGetHkdf(uint64(src))
		if s == nil {
			return 0
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		// The dup must carry the mode too; otherwise an EXTRACT_ONLY or
		// EXPAND_ONLY dup computes extract-and-expand and its output
		// differs from the default provider's PRK.
		n := &hkdfCtx{hashFn: s.hashFn,
			salt: append([]byte(nil), s.salt...),
			key:  append([]byte(nil), s.key...),
			info: append([][]byte(nil), s.info...),
			mode: s.mode, modeSet: s.modeSet}
		return C.uint64_t(regPut(n))
	})
}

// ---- AES-GCM (OSSL_OP_CIPHER), one-shot model, fail-closed on streaming ----

// GCM nonce uniqueness is per key instance: the Go module's TLS 1.3 GCM
// service (gcm_tls13.go) requires the record counter to strictly increase.
// A ctx copy shares its instance with the original, and re-keying a ctx
// with the same key keeps it. The same key bytes loaded into a new ctx are
// a new instance whose counter starts again, as in crypto/tls; TLS derives
// a fresh key per connection. Application-level GCM is outside the claim.

type gcmCtx struct {
	mu         sync.Mutex
	aead       *tls13GCM    // GCM: the module's TLS 1.3 GCM service (gcm_tls13.go)
	block      cipher.Block // CBC mode: raw AES block primitive
	cbc        bool         // true when this ctx is AES-*-CBC
	enc        bool
	keyLen     int
	algKeyLen  int // the registered algorithm's key length (32 or 16); 0 = 256-GCM legacy ctx
	ivLen      int
	nonce      []byte   // per-op nonce captured at init
	iv         []byte   // CBC: current chaining IV
	iv0        []byte   // CBC: the IV as set, restored by a re-init without one
	buf        []byte   // one-shot buffer (update accumulates; final seals/opens)
	aad        []byte   // additional authenticated data (TLS record header)
	tag        []byte   // pending tag (encrypt-final sets; decrypt-final verifies)
	tagIn      []byte   // caller-supplied tag for decrypt
	sealed     bool     // a Seal/Open ran for the current nonce (ctx finalized)
	sawData    bool     // a DATA update ran for the current nonce (one data update max)
	keyFP      [32]byte // SHA-256 of the key: the nonce-guard's per-key identity
	hasKeyFP   bool
	key12      []byte            // GCM key, kept for TLS 1.2 mode (set by tlsivfixed)
	sealedKeys map[[32]byte]bool // encrypt keys this ctx used before the current one
	tls12      *tls12GCM         // TLS 1.2 record mode (tls12.go)
	tlsAAD     []byte            // the current TLS 1.2 record's AAD
	ivOut      [2]unsafe.Pointer // C copies of the IV (0) and updated IV (1) for OCTET_PTR queries
}

// ivPtr copies iv into the ctx's C buffer for slot and returns it. The
// pointer EVP_CIPHER_CTX_iv() hands out must stay valid, so the buffer
// lives until freectx. Called with ctx.mu held; iv is at most 16 bytes.
func (ctx *gcmCtx) ivPtr(slot int, iv []byte) unsafe.Pointer {
	if ctx.ivOut[slot] == nil {
		ctx.ivOut[slot] = C.malloc(16)
	}
	buf := unsafe.Slice((*byte)(ctx.ivOut[slot]), 16)
	clear(buf)
	copy(buf, iv)
	return ctx.ivOut[slot]
}

func (ctx *gcmCtx) freeIVOut() {
	for i, p := range ctx.ivOut {
		if p != nil {
			C.free(p)
			ctx.ivOut[i] = nil
		}
	}
}

// withLock runs fn holding mu and releases it on every exit, including a
// panic. opGuard turns a panic into a refusal but cannot release a mutex:
// a lock left held by a panicking call makes the next call on that ctx
// wait forever. Any hash or cipher call made while holding a ctx lock
// goes through here.
func withLock(mu *sync.Mutex, fn func()) {
	mu.Lock()
	defer mu.Unlock()
	fn()
}

// opGuard converts a panic in any provider operation into a clean
// refusal: the deferred recover sets the named return to 0, so the cgo
// boundary always sees an EVP error, never a Go panic (a panic cannot
// unwind through a C frame; it would abort the host).
// A panic is never converted into success. Every wrapped export shares
// this one helper; the named-return pattern needs no global state and
// is race-free (each invocation has its own rc).
func opGuard(fn func() C.int) (rc C.int) {
	defer func() {
		if r := recover(); r != nil {
			dbg("provider op PANIC recovered (refused, not success): %v", r)
			rc = 0
		}
	}()
	return fn()
}

// handleGuard is opGuard for exports that return a handle: a panic
// returns 0 (no object), which callers treat as an allocation failure.
func handleGuard(fn func() C.uint64_t) (h C.uint64_t) {
	defer func() {
		if r := recover(); r != nil {
			dbg("provider handle op PANIC recovered (refused): %v", r)
			h = 0
		}
	}()
	return fn()
}

//export gofips_cipher_newctx
func gofips_cipher_newctx(provctx *C.void) C.uint64_t {
	return handleGuard(func() C.uint64_t {
		dbg("cipher_newctx")
		_ = provctx
		return C.uint64_t(regPut(&gcmCtx{ivLen: 12, algKeyLen: 32}))
	})
}

//export gofips_cipher128_newctx
func gofips_cipher128_newctx(provctx *C.void) C.uint64_t {
	return handleGuard(func() C.uint64_t {
		dbg("cipher128_newctx")
		_ = provctx
		return C.uint64_t(regPut(&gcmCtx{ivLen: 12, keyLen: 16, algKeyLen: 16}))
	})
}

//export gofips_cipher128_freectx
func gofips_cipher128_freectx(cctx C.uint64_t) {
	gofips_cipher_freectx(cctx)
}

//export gofips_cipher128_dupctx
func gofips_cipher128_dupctx(cctx C.uint64_t) C.uint64_t {
	return handleGuard(func() C.uint64_t {
		s := regGetGcm(uint64(cctx))
		if s == nil {
			return 0
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		// Same field set as gofips_cipher_dupctx below; the dup shares the
		// module GCM instance, so the record counter covers both.
		n := &gcmCtx{keyLen: s.keyLen, algKeyLen: s.algKeyLen, ivLen: s.ivLen, enc: s.enc,
			aead: s.aead, nonce: append([]byte(nil), s.nonce...), sealed: s.sealed,
			keyFP: s.keyFP, hasKeyFP: s.hasKeyFP,
			aad: append([]byte(nil), s.aad...), buf: append([]byte(nil), s.buf...),
			tagIn: append([]byte(nil), s.tagIn...), tag: append([]byte(nil), s.tag...),
			sawData: s.sawData,
			key12:   append([]byte(nil), s.key12...), tls12: s.tls12, tlsAAD: append([]byte(nil), s.tlsAAD...),
			sealedKeys: maps.Clone(s.sealedKeys)}
		return C.uint64_t(regPut(n))
	})
}

//export gofips_cbc_newctx
func gofips_cbc_newctx(provctx *C.void) C.uint64_t {
	return handleGuard(func() C.uint64_t {
		dbg("cbc_newctx")
		_ = provctx
		return C.uint64_t(regPut(&gcmCtx{cbc: true, ivLen: 16, algKeyLen: 32}))
	})
}

// AES-128-CBC: Node's TLS session-ticket callback encrypts tickets with it.
//
//export gofips_cbc128_newctx
func gofips_cbc128_newctx(provctx *C.void) C.uint64_t {
	return handleGuard(func() C.uint64_t {
		_ = provctx
		return C.uint64_t(regPut(&gcmCtx{cbc: true, ivLen: 16, algKeyLen: 16}))
	})
}

//export gofips_cbc_freectx
func gofips_cbc_freectx(cctx C.uint64_t) {
	if ctx := regGetGcm(uint64(cctx)); ctx != nil {
		withLock(&ctx.mu, ctx.freeIVOut)
	}
	regDel(uint64(cctx))
}

//export gofips_cbc_dupctx
func gofips_cbc_dupctx(cctx C.uint64_t) C.uint64_t {
	return handleGuard(func() C.uint64_t {
		s := regGetGcm(uint64(cctx))
		if s == nil {
			return 0
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		n := &gcmCtx{cbc: true, keyLen: s.keyLen, algKeyLen: s.algKeyLen, ivLen: 16, enc: s.enc,
			block:  s.block,
			iv:     append([]byte(nil), s.iv...),
			iv0:    append([]byte(nil), s.iv0...),
			buf:    append([]byte(nil), s.buf...),
			sealed: s.sealed}
		return C.uint64_t(regPut(n))
	})
}

//export gofips_cipher_freectx
func gofips_cipher_freectx(cctx C.uint64_t) {
	if ctx := regGetGcm(uint64(cctx)); ctx != nil {
		withLock(&ctx.mu, func() { clear(ctx.key12); ctx.key12 = nil; ctx.freeIVOut() })
	}
	regDel(uint64(cctx))
}

//export gofips_cipher_dupctx
func gofips_cipher_dupctx(cctx C.uint64_t) C.uint64_t {
	return handleGuard(func() C.uint64_t {
		s := regGetGcm(uint64(cctx))
		if s == nil {
			return 0
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		// Full clone: libssl dups record-layer ctxs that are already keyed, so
		// the dup carries the key, AEAD, nonce and mode state.
		// The dup shares the module GCM instance (aead) with the original, so
		// the module's record counter covers both: a nonce sealed through one
		// cannot be sealed again through the other. AAD, buffer, tag and
		// per-nonce data state are copied.
		n := &gcmCtx{keyLen: s.keyLen, algKeyLen: s.algKeyLen, ivLen: s.ivLen, enc: s.enc,
			aead: s.aead, block: s.block, cbc: s.cbc,
			nonce:  append([]byte(nil), s.nonce...),
			iv:     append([]byte(nil), s.iv...),
			iv0:    append([]byte(nil), s.iv0...),
			sealed: s.sealed,
			keyFP:  s.keyFP, hasKeyFP: s.hasKeyFP,
			aad: append([]byte(nil), s.aad...), buf: append([]byte(nil), s.buf...),
			tagIn: append([]byte(nil), s.tagIn...), tag: append([]byte(nil), s.tag...),
			sawData: s.sawData,
			key12:   append([]byte(nil), s.key12...), tls12: s.tls12, tlsAAD: append([]byte(nil), s.tlsAAD...),
			sealedKeys: maps.Clone(s.sealedKeys)}
		return C.uint64_t(regPut(n))
	})
}

//export gofips_cipher_encrypt_init
func gofips_cipher_encrypt_init(cctx C.uint64_t, key *C.uchar, keylen C.size_t, iv *C.uchar, ivlen C.size_t, params *C.OSSL_PARAM) C.int {
	return opGuard(func() C.int { return cipher_encrypt_initOp(cctx, key, keylen, iv, ivlen, params) })
}

func cipher_encrypt_initOp(cctx C.uint64_t, key *C.uchar, keylen C.size_t, iv *C.uchar, ivlen C.size_t, params *C.OSSL_PARAM) C.int {
	return gcmInit(cctx, key, keylen, iv, ivlen, params, true)
}

//export gofips_cipher_decrypt_init
func gofips_cipher_decrypt_init(cctx C.uint64_t, key *C.uchar, keylen C.size_t, iv *C.uchar, ivlen C.size_t, params *C.OSSL_PARAM) C.int {
	return opGuard(func() C.int { return cipher_decrypt_initOp(cctx, key, keylen, iv, ivlen, params) })
}

func cipher_decrypt_initOp(cctx C.uint64_t, key *C.uchar, keylen C.size_t, iv *C.uchar, ivlen C.size_t, params *C.OSSL_PARAM) C.int {
	return gcmInit(cctx, key, keylen, iv, ivlen, params, false)
}

func gcmInit(cctx C.uint64_t, key *C.uchar, keylen C.size_t, iv *C.uchar, ivlen C.size_t, params *C.OSSL_PARAM, enc bool) C.int {
	dbg("gcmInit ENTER cctx=%d keylen=%d ivlen=%d key=%v iv=%v", int64(cctx), int(keylen), int(ivlen), key != nil, iv != nil)
	ctx := regGetGcm(uint64(cctx))
	if ctx == nil {
		dbg("gcmInit fail: nil ctx")
		return 0
	}
	if ctx.cbc && ivlen == 12 {
		// CBC IVs are 16 bytes; 12 is accepted only as "no IV yet".
		dbg("gcmInit CBC got ivlen=12 (expected 16)")
	}
	// OpenSSL may call init twice: keyless (params/iv setup) then keyed.
	// Accept a keyless call that carries an IV; require the key before
	// any update/final.
	if key == nil || keylen == 0 {
		if ctx.cbc {
			// As the default provider: a new IV replaces the chaining
			// state, and a re-init without one restarts from the IV as set.
			ctx.mu.Lock()
			defer ctx.mu.Unlock()
			if iv != nil {
				if ivlen != 16 {
					return 0
				}
				ctx.iv0 = append([]byte(nil), unsafe.Slice((*byte)(unsafe.Pointer(iv)), 16)...)
			}
			if ctx.iv0 != nil {
				ctx.iv = append([]byte(nil), ctx.iv0...)
			}
			ctx.enc = enc
			ctx.buf = nil
			return 1
		}
		// Per-record re-init (TLS record layer): fresh nonce + reset
		// per-record state. The key/AEAD persist, and so does the
		// direction: a keyless re-init cannot turn an encrypt ctx into a
		// decrypt one (its final would then verify nothing).
		var nonce []byte
		if iv != nil && ivlen == 12 {
			nonce = append([]byte(nil), unsafe.Slice((*byte)(unsafe.Pointer(iv)), 12)...)
		}
		ctx.mu.Lock()
		if ctx.hasKeyFP && enc != ctx.enc {
			ctx.mu.Unlock()
			return 0
		}
		if nonce != nil {
			ctx.ivLen = 12
			ctx.nonce = nonce
			// The module's TLS 1.3 GCM (gcm_tls13.go) checks the counter.
			ctx.sealed = false // fresh nonce: the ctx is usable again
		}
		ctx.buf = nil
		ctx.aad = nil
		ctx.tag = nil
		ctx.tagIn = nil
		ctx.sawData = false
		ctx.mu.Unlock()
		dbg("gcmInit keyless call done (iv=%v)", iv != nil)
		return 1
	}
	// Every check runs, and the caller's key and IV are copied, before the
	// ctx changes: a refused init leaves it as it was.
	// The ctx's registered algorithm fixes the key length (algKeyLen: 16
	// for AES-128, 32 for AES-256). A key of any other length is refused:
	// a 32-byte key on the 128 algorithm would silently run AES-256.
	algLen := ctx.algKeyLen
	if algLen == 0 {
		algLen = 32 // AES-256-GCM default ctx
	}
	if int(keylen) != algLen {
		dbg("gcmInit REFUSED: keylen=%d algorithm requires %d", int(keylen), algLen)
		return 0
	}
	keyBytes := append([]byte(nil), unsafe.Slice((*byte)(unsafe.Pointer(key)), algLen)...)
	defer clear(keyBytes)
	var ivBytes []byte
	if iv != nil && ivlen > 0 {
		// CBC IVs are 16 bytes; the TLS 1.3 GCM nonce is 12.
		if (ctx.cbc && ivlen != 16) || (!ctx.cbc && ivlen != 12) {
			return 0
		}
		ivBytes = append([]byte(nil), unsafe.Slice((*byte)(unsafe.Pointer(iv)), int(ivlen))...)
	} else if ctx.cbc {
		return 0
	}
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return 0
	}
	newFP := sha256.Sum256(keyBytes)
	ctx.mu.Lock()
	defer ctx.mu.Unlock()
	// Same key bytes on a ctx that is already keyed for GCM in the same
	// direction: keep the module instance so its record counter continues.
	sameKey := ctx.hasKeyFP && ctx.keyFP == newFP && ctx.enc == enc && ctx.aead != nil && !ctx.cbc
	// An encrypt ctx never returns to a key it sealed under before: the
	// new instance's counter would restart and repeat nonces.
	if enc && !ctx.cbc && !sameKey && ctx.sealedKeys[newFP] {
		return 0
	}
	if ctx.hasKeyFP && ctx.enc && !ctx.cbc {
		if ctx.sealedKeys == nil {
			ctx.sealedKeys = map[[32]byte]bool{}
		}
		ctx.sealedKeys[ctx.keyFP] = true
	}
	ctx.keyFP = newFP
	ctx.hasKeyFP = true
	ctx.enc = enc
	ctx.keyLen = int(keylen)
	ctx.sawData = false
	ctx.sealed = false
	ctx.buf = nil
	if ctx.cbc {
		// AES-CBC (session tickets): the standard library's CBC chaining
		// over the module's AES block; registered without fips=yes.
		ctx.block = block
		ctx.iv0 = ivBytes
		ctx.iv = append([]byte(nil), ivBytes...)
		ctx.aead = nil
		return 1
	}
	// The AEAD is the module's TLS 1.3 GCM service, reached through
	// gcm_tls13.go, not cipher.NewGCM. cipher.NewGCM is the arbitrary-nonce
	// path: non-approved for encryption, and rejected outright under
	// GODEBUG=fips140=only.
	if !sameKey {
		ctx.aead = newTLS13GCM(keyBytes)
		clear(ctx.key12)
		ctx.key12 = append([]byte(nil), keyBytes...)
		ctx.tls12 = nil
	}
	ctx.tlsAAD = nil
	ctx.aad = nil
	ctx.tag = nil
	ctx.tagIn = nil
	if ivBytes != nil {
		// The nonce goes to the module's TLS 1.3 GCM at seal/open time; it
		// learns the static IV from the first record and refuses a counter
		// that does not increase, within this key instance.
		ctx.ivLen = 12
		ctx.nonce = ivBytes
	}
	return 1
}

//export gofips_cipher_update
func gofips_cipher_update(cctx C.uint64_t, out *C.uchar, outl *C.size_t, outsz C.size_t, in *C.uchar, inl C.size_t) C.int {
	return opGuard(func() C.int { return cipherUpdate(cctx, out, outl, outsz, in, inl) })
}

func cipherUpdate(cctx C.uint64_t, out *C.uchar, outl *C.size_t, outsz C.size_t, in *C.uchar, inl C.size_t) C.int {
	ctx := regGetGcm(uint64(cctx))
	dbg("cipher_update cctx=%d inl=%d enc=%v out=%v in=%v outl=%v", int64(cctx), int(inl), ctx != nil && ctx.enc, out != nil, in != nil, outl != nil)
	if ctx == nil || outl == nil || (in == nil && inl > 0) {
		return 0
	}
	*outl = 0
	ctx.mu.Lock()
	defer ctx.mu.Unlock()
	if ctx.aead == nil && !ctx.cbc {
		return 0
	}
	if ctx.tls12 != nil && ctx.tlsAAD != nil {
		return tls12Record(ctx, out, outl, outsz, in, inl)
	}
	// Go's cipher.AEAD is one-shot per nonce, so GCM accepts one data
	// update per nonce (below).
	// AAD: OpenSSL signals additional data with out==NULL && in != NULL
	// (TLS record header). The sizing pass (out==NULL && in==NULL) only
	// reports capacity.
	if out == nil {
		if in == nil {
			*outl = 0
			return 1
		}
		if !ctx.cbc && (ctx.sawData || ctx.sealed) {
			return 0 // AAD after the data would not be in the tag
		}
		aadBytes := unsafe.Slice((*byte)(unsafe.Pointer(in)), int(inl))
		ctx.aad = append(ctx.aad, aadBytes...)
		*outl = 0
		return 1
	}
	ib := unsafe.Slice((*byte)(unsafe.Pointer(in)), int(inl))
	// CBC streaming: process whole 16-byte blocks now, buffer the rest.
	if ctx.cbc {
		if ctx.block == nil || ctx.iv == nil {
			return 0
		}
		if int(outsz) < int(inl) {
			return 0
		}
		outB := unsafe.Slice((*byte)(unsafe.Pointer(out)), int(outsz))
		data := append(ctx.buf, ib...)
		if ctx.enc {
			// Encrypt via the standard library's CBC chaining
			// (approved-mode SP 800-38A construction over the module's
			// AES block primitive): whole blocks now, partial tail
			// buffered for final.
			n := len(data) / 16 * 16
			if n > 0 {
				cipher.NewCBCEncrypter(ctx.block, ctx.iv).CryptBlocks(outB[:n], data[:n])
				// The next IV is the last ciphertext block.
				copy(ctx.iv, outB[n-16:n])
			}
			ctx.buf = append([]byte(nil), data[n:]...)
			*outl = C.size_t(n)
			return 1
		}
		// Decrypt: hold back the last full block (the padding check at
		// final needs the second-to-last chaining IV).
		if len(data) < 32 {
			ctx.buf = data
			*outl = 0
			return 1
		}
		n := (len(data) - 16) / 16 * 16
		if n > 0 {
			cipher.NewCBCDecrypter(ctx.block, ctx.iv).CryptBlocks(outB[:n], data[:n])
			copy(ctx.iv, data[n-16:n])
		}
		ctx.buf = append([]byte(nil), data[n:]...)
		*outl = C.size_t(n)
		return 1
	}
	// GCM: the one-shot Go AEAD supports one Seal/Open per nonce. The
	// record path (tag known before the updates) opens at the first data
	// update; the encrypt path seals the single data update. A second
	// data update is refused (streaming would reuse the keystream).
	if ctx.sealed {
		// One Seal/Open per nonce: re-init with a fresh nonce first.
		dbg("cipher_update REFUSED: ctx finalized; re-init with a fresh nonce required")
		return 0
	}
	if !ctx.enc && ctx.tagIn != nil {
		// Decrypt with the tag known (the TLS record layer sets it before
		// the data): open the buffered ciphertext plus this chunk and emit
		// this chunk's plaintext now, as the default provider does.
		if ctx.nonce == nil {
			// No IV set: refuse before Open.
			dbg("cipher_update REFUSED: decrypt with tag but no IV set (nonce nil)")
			return 0
		}
		ctAll := append(append([]byte(nil), ctx.buf...), ib...)
		ctFull := append(append([]byte(nil), ctAll...), ctx.tagIn...)
		ptAll, err := ctx.aead.Open(ctx.nonce, ctFull, ctx.aad)
		if err != nil {
			dbg("decrypt update Open FAILED: %v", err)
			return 0 // tag mismatch, fail closed
		}
		if int(outsz) < len(ib) {
			dbg("cipher_update REFUSED: decrypt outsz=%d < chunk=%d", int(outsz), len(ib))
			return 0
		}
		if out == nil && len(ib) > 0 {
			return 0
		}
		copy(unsafe.Slice((*byte)(unsafe.Pointer(out)), len(ib)), ptAll[len(ptAll)-len(ib):])
		*outl = C.size_t(len(ib))
		ctx.buf = ctAll
		ctx.sealed = true
		recordOp("cipher")
		return 1
	}
	if ctx.sawData {
		// A second data update: Go's cipher.AEAD permits one Seal/Open
		// per nonce, and sealing per update would reuse the keystream.
		// The TLS record layer issues one data update per record; a
		// streaming GCM caller gets a refusal, not wrong bytes.
		dbg("cipher_update REFUSED: a second data update on the one-shot GCM model (streaming not supported; re-init with a fresh nonce)")
		return 0
	}
	if ctx.nonce == nil {
		// No IV set: refuse before Seal.
		dbg("cipher_update REFUSED: keyed encrypt with no IV set (nonce nil)")
		return 0
	}
	ctx.sawData = true
	ctx.buf = append(ctx.buf, ib...)
	if ctx.enc {
		// Single-data-update model: seal the whole (one-update)
		// message now and emit ct at update, matching the default
		// provider's streaming placement and EVP's update-time buffer
		// sizing. Exactly one data update is accepted per nonce (the
		// refusal above); the tag is read at final via get_ctx_params.
		// EVP sizes the update buffer as inl + blocksize (ct only;
		// the tag goes via get_ctx_params at final); do not demand
		// tag space here.
		if int(outsz) < len(ctx.buf) {
			dbg("cipher_update REFUSED: outsz=%d < ct=%d", int(outsz), len(ctx.buf))
			return 0
		}
		ct, serr := ctx.aead.Seal(ctx.nonce, ctx.buf, ctx.aad)
		if serr != nil {
			dbg("cipher_update REFUSED: %v", serr)
			return 0
		}
		tagOff := len(ct) - ctx.aead.Overhead()
		copy(unsafe.Slice((*byte)(unsafe.Pointer(out)), tagOff), ct[:tagOff])
		*outl = C.size_t(tagOff)
		ctx.tag = append([]byte(nil), ct[tagOff:]...)
		if debugEnabled {
			dbg("encrypt ok: nonce=%x aad=%x(%d) pt(%d)=%x ct[:8]=%x tag=%x outsz=%d", ctx.nonce, ctx.aad, len(ctx.aad), len(ctx.buf), ctx.buf, ct[:8], ctx.tag, int(outsz))
		}
		ctx.sealed = true
		ctx.buf = nil
		ctx.aad = nil
		recordOp("cipher")
		return 1
	}
	if debugEnabled {
		head := ib
		if len(head) > 16 {
			head = head[:16]
		}
		dbg("decrypt update buffered inl=%d head=%x total=%d", int(inl), head, len(ctx.buf))
	}
	// Decrypt before the tag is known: the bytes are buffered and nothing
	// is produced. Go's AEAD releases plaintext only after it has verified
	// the tag, so there is nothing to hand back yet.
	*outl = 0
	return 1
}

//export gofips_cipher_final
func gofips_cipher_final(cctx C.uint64_t, out *C.uchar, outl *C.size_t, outsz C.size_t) C.int {
	return opGuard(func() C.int { return cipherFinal(cctx, out, outl, outsz) })
}

func cipherFinal(cctx C.uint64_t, out *C.uchar, outl *C.size_t, outsz C.size_t) C.int {
	dbg("cipher_final outsz=%d enc-state", int(outsz))
	ctx := regGetGcm(uint64(cctx))
	if ctx == nil || outl == nil {
		return 0
	}
	ctx.mu.Lock()
	defer ctx.mu.Unlock()
	if ctx.aead == nil && !ctx.cbc {
		return 0
	}
	if ctx.cbc {
		// CBC final: PKCS#7 pad (encrypt) / unpad (decrypt).
		outB := unsafe.Slice((*byte)(unsafe.Pointer(out)), outsz)
		if ctx.enc {
			pad := 16 - len(ctx.buf)%16
			padded := append(ctx.buf, make([]byte, pad)...)
			for i := len(ctx.buf); i < len(padded); i++ {
				padded[i] = byte(pad)
			}
			if int(outsz) < len(padded) {
				return 0
			}
			cipher.NewCBCEncrypter(ctx.block, ctx.iv).CryptBlocks(outB[:len(padded)], padded)
			*outl = C.size_t(len(padded))
			ctx.buf = nil
			recordOp("cipher")
			return 1
		}
		// decrypt: the final block(s) are in ctx.buf; the chaining IV
		// for them is ctx.iv (updated by the last update call).
		if len(ctx.buf) == 0 || len(ctx.buf)%16 != 0 {
			return 0
		}
		pt := make([]byte, len(ctx.buf))
		cipher.NewCBCDecrypter(ctx.block, ctx.iv).CryptBlocks(pt, ctx.buf)
		pad := int(pt[len(pt)-1])
		if pad <= 0 || pad > 16 || pad > len(pt) {
			return 0
		}
		for i := len(pt) - pad; i < len(pt); i++ {
			if int(pt[i]) != pad {
				return 0
			}
		}
		pt = pt[:len(pt)-pad]
		if int(outsz) < len(pt) {
			return 0
		}
		copy(outB, pt)
		*outl = C.size_t(len(pt))
		ctx.buf = nil
		recordOp("cipher")
		return 1
	}
	if ctx.enc {
		// Encrypt final: the single data update already sealed and
		// emitted ct (update-time emission matches the default
		// provider's placement). Final emits nothing for a non-empty
		// message; for an empty plaintext (no data update ever ran, as in
		// the NIST GCM empty-PT vector) seal now: GCM over a
		// zero-length message with the captured nonce/AAD, tag only.
		if ctx.sealed {
			*outl = 0
			return 1
		}
		if ctx.aead == nil || ctx.nonce == nil {
			return 0
		}
		ct, serr := ctx.aead.Seal(ctx.nonce, []byte{}, ctx.aad)
		if serr != nil {
			dbg("cipher_final REFUSED: %v", serr)
			return 0
		}
		// GCM final emits no bytes: the ciphertext of an empty message
		// is empty, and the tag is read with get_ctx_params (the default
		// provider's contract).
		*outl = 0
		ctx.tag = append([]byte(nil), ct[len(ct)-ctx.aead.Overhead():]...)
		ctx.buf = nil
		ctx.aad = nil
		ctx.sealed = true
		recordOp("cipher")
		return 1
	}
	// decrypt: open the buffered ciphertext with the caller-supplied tag.
	// With the tag set first, the plaintext was emitted at update: final
	// emits nothing and succeeds (libssl calls it after every record).
	if ctx.sealed {
		*outl = 0
		return 1
	}
	if len(ctx.tagIn) != ctx.aead.Overhead() {
		// Wrong-tag-size refusal: diagnostic-only (dbg is compiled out
		// of release builds; no unconditional stderr in release).
		dbg("decrypt final REFUSED: tagIn=%d != Overhead=%d", len(ctx.tagIn), ctx.aead.Overhead())
		return 0
	}
	if ctx.nonce == nil {
		// Decrypt keyed with tag but no IV ever set: the
		// Open(nil nonce) panic is contained at update already; this
		// covers a tag set after updates with no IV. Refuse before Open.
		dbg("cipher_final REFUSED: decrypt with tag but no IV set (nonce nil)")
		return 0
	}
	if len(ctx.buf) > 0 {
		// The tag arrived after the data. EVP gives final no output space
		// for GCM, so refuse: set the tag before the data, as the TLS
		// record layer and Node's createDecipheriv do.
		dbg("cipher_final REFUSED: GCM tag was set after the data; set the tag before update")
		return 0
	}
	// No data was buffered: an AAD-only (empty ciphertext) message. Verify
	// the tag; there is no plaintext to emit.
	if _, err := ctx.aead.Open(ctx.nonce, append([]byte(nil), ctx.tagIn...), ctx.aad); err != nil {
		dbg("decrypt Open FAILED: %v", err)
		return 0 // tag mismatch, fail closed
	}
	ctx.sealed = true
	*outl = 0
	ctx.buf = nil
	ctx.aad = nil
	recordOp("cipher")
	return 1
}

//export gofips_cipher_cipher
func gofips_cipher_cipher(cctx C.uint64_t, out *C.uchar, outl *C.size_t, outsz C.size_t, in *C.uchar, inl C.size_t) C.int {
	return opGuard(func() C.int { return cipherCipher(cctx, out, outl, outsz, in, inl) })
}

// cipherCipher is the one-shot path (legacy EVP_Cipher): buffer+seal/open
// in a single call, under the same panic containment as update/final.
func cipherCipher(cctx C.uint64_t, out *C.uchar, outl *C.size_t, outsz C.size_t, in *C.uchar, inl C.size_t) C.int {
	dbg("cipher_cipher inl=%d", int(inl))
	ctx := regGetGcm(uint64(cctx))
	if ctx == nil || outl == nil || (in == nil && inl > 0) {
		return 0
	}
	ctx.mu.Lock()
	defer ctx.mu.Unlock()
	if ctx.tls12 != nil && ctx.tlsAAD != nil {
		return tls12Record(ctx, out, outl, outsz, in, inl)
	}
	if in == nil && ctx.sealed {
		// Final after the data, as cipher_final: the tag was computed or
		// verified with the data, so it succeeds with no output.
		*outl = 0
		return 1
	}
	if ctx.aead == nil || ctx.nonce == nil || ctx.sealed || ctx.sawData {
		return 0
	}
	ib := unsafe.Slice((*byte)(unsafe.Pointer(in)), int(inl))
	if out == nil && in != nil {
		ctx.aad = append(ctx.aad, ib...)
		*outl = 0
		return 1
	}
	if ctx.enc {
		ct, serr := ctx.aead.Seal(ctx.nonce, ib, ctx.aad)
		if serr != nil {
			dbg("cipher_cipher REFUSED: %v", serr)
			return 0
		}
		tagOff := len(ct) - ctx.aead.Overhead()
		if tagOff < 0 || int(outsz) < tagOff {
			return 0
		}
		copy(unsafe.Slice((*byte)(unsafe.Pointer(out)), tagOff), ct[:tagOff])
		*outl = C.size_t(tagOff)
		ctx.tag = append([]byte(nil), ct[tagOff:]...)
		ctx.sealed = true
		ctx.aad = nil
		recordCall()
		return 1
	}
	if len(ctx.tagIn) != ctx.aead.Overhead() {
		return 0
	}
	pt, err := ctx.aead.Open(ctx.nonce, append(append([]byte(nil), ib...), ctx.tagIn...), ctx.aad)
	if err != nil {
		return 0
	}
	if int(outsz) < len(pt) {
		return 0
	}
	copy(unsafe.Slice((*byte)(unsafe.Pointer(out)), len(pt)), pt)
	*outl = C.size_t(len(pt))
	ctx.sealed = true
	ctx.aad = nil
	recordCall()
	return 1
}

//export gofips_cipher_get_params
func gofips_cipher_get_params(params *C.OSSL_PARAM) C.int {
	return opGuard(func() C.int { return cipher_get_paramsOp(params) })
}

func cipher_get_paramsOp(params *C.OSSL_PARAM) C.int {
	return cipherParams(params, 32, 12)
}

//export gofips_cipher128_get_params
func gofips_cipher128_get_params(params *C.OSSL_PARAM) C.int {
	return opGuard(func() C.int { return cipher128_get_paramsOp(params) })
}

func cipher128_get_paramsOp(params *C.OSSL_PARAM) C.int {
	return cipherParams(params, 16, 12)
}

//export gofips_cbc_get_params
func gofips_cbc_get_params(params *C.OSSL_PARAM) C.int {
	return opGuard(func() C.int { return cbc_get_paramsOp(params) })
}

func cbc_get_paramsOp(params *C.OSSL_PARAM) C.int {
	return cbcParams(params, 32, 16)
}

//export gofips_cbc128_get_params
func gofips_cbc128_get_params(params *C.OSSL_PARAM) C.int {
	return opGuard(func() C.int { return cbcParams(params, 16, 16) })
}

func cbcParams(params *C.OSSL_PARAM, keylen, ivlen uint64) C.int {
	if params == nil {
		return 0
	}
	ok := 1
	for i := 0; i < paramCount(params); i++ {
		p := paramAt(params, i)
		if p.key == nil {
			break
		}
		switch C.GoString(p.key) {
		case C.OSSL_CIPHER_PARAM_KEYLEN:
			if !setUint(p, keylen) {
				ok = 0
			}
		case C.OSSL_CIPHER_PARAM_IVLEN:
			if !setUint(p, ivlen) {
				ok = 0
			}
		case C.OSSL_CIPHER_PARAM_MODE:
			if !setUint32(p, 2) { // EVP_CIPH_CBC_MODE
				ok = 0
			}
		case C.OSSL_CIPHER_PARAM_BLOCK_SIZE:
			if !setUint(p, 16) {
				ok = 0
			}
		case C.OSSL_CIPHER_PARAM_CUSTOM_IV:
			if !setUint(p, 1) {
				ok = 0
			}
		}
	}
	return C.int(ok)
}

//export gofips_cipher_get_ctx_params
func gofips_cipher_get_ctx_params(cctx C.uint64_t, params *C.OSSL_PARAM) C.int {
	return opGuard(func() C.int { return cipher_get_ctx_paramsOp(cctx, params) })
}

func cipher_get_ctx_paramsOp(cctx C.uint64_t, params *C.OSSL_PARAM) C.int {
	ctx := regGetGcm(uint64(cctx))
	if ctx == nil || params == nil {
		return 0
	}
	ok := 1
	for i := 0; i < paramCount(params); i++ {
		p := paramAt(params, i)
		if p.key == nil {
			break
		}
		switch C.GoString(p.key) {
		case C.OSSL_CIPHER_PARAM_KEYLEN:
			// Report the registered algorithm's key length (32 for
			// AES-256-GCM, 16 for AES-128-GCM), not the ctx's current
			// state: EVP sizes the key buffer from this and gcmInit
			// refuses any other length.
			kl := uint64(ctx.algKeyLen)
			if kl == 0 {
				kl = 32
			}
			if !setUint(p, kl) {
				ok = 0
			}
		case C.OSSL_CIPHER_PARAM_IVLEN:
			ivl := uint64(12)
			withLock(&ctx.mu, func() {
				if ctx.cbc {
					ivl = 16
				}
			})
			if !setUint(p, ivl) {
				ok = 0
			}
		case C.OSSL_CIPHER_PARAM_AEAD_TAGLEN:
			// EVP_CIPHER_CTX_tag_length queries the CTX (not the
			// static cipher); the TLS record layer calls it before
			// each record's cipher pass.
			dbg("cipher_get_ctx_params: taglen query")
			if !setUint(p, 16) {
				ok = 0
			}
		case C.OSSL_CIPHER_PARAM_BLOCK_SIZE:
			if !setUint(p, 1) {
				ok = 0
			}
		case C.OSSL_CIPHER_PARAM_AEAD_TAG:
			// As the default provider: after an encrypt, the first
			// data_size bytes of the tag. Only 96 to 128 bits (SP 5247
			// Table 6); anything else, or no tag yet, is an error.
			var tag []byte
			withLock(&ctx.mu, func() {
				if ctx.enc {
					tag = append([]byte(nil), ctx.tag...)
				}
			})
			n := int(p.data_size)
			if len(tag) != 16 || p.data == nil || n < 12 || n > 16 {
				ok = 0
			} else {
				copy(unsafe.Slice((*byte)(unsafe.Pointer(p.data)), n), tag[:n])
				p.return_size = C.size_t(n)
			}
		case C.OSSL_CIPHER_PARAM_AEAD_TLS1_AAD_PAD:
			// The tag a TLS 1.2 record carries after its data.
			ctx.mu.Lock()
			set := ctx.tls12 != nil && ctx.tlsAAD != nil
			ctx.mu.Unlock()
			if !set || !setUint(p, tls12Tag) {
				ok = 0
			}
		case C.OSSL_CIPHER_PARAM_IV, C.OSSL_CIPHER_PARAM_UPDATED_IV:
			// CBC: the IV as set, or the current chaining IV. GCM: the
			// nonce as set. A TLS 1.2 GCM ctx builds each record's nonce
			// itself and has no single IV to report.
			// Both forms are answered, as the default provider: a copy
			// (OCTET_STRING) or a pointer (OCTET_PTR, EVP_CIPHER_CTX_iv).
			updated := C.GoString(p.key) == C.OSSL_CIPHER_PARAM_UPDATED_IV
			dt := p.data_type
			var iv []byte
			var ptr unsafe.Pointer
			withLock(&ctx.mu, func() {
				switch {
				case ctx.cbc && !updated:
					iv = ctx.iv0
				case ctx.cbc:
					iv = ctx.iv
				case ctx.tls12 == nil:
					iv = ctx.nonce
				}
				iv = append([]byte(nil), iv...)
				if len(iv) > 0 && dt == C.OSSL_PARAM_OCTET_PTR {
					slot := 0
					if updated {
						slot = 1
					}
					ptr = ctx.ivPtr(slot, iv)
				}
			})
			switch {
			case len(iv) == 0:
				ok = 0
			case dt == C.OSSL_PARAM_OCTET_STRING:
				if !setOctet(p, iv) {
					ok = 0
				}
			case dt == C.OSSL_PARAM_OCTET_PTR && p.data != nil:
				*(*unsafe.Pointer)(unsafe.Pointer(p.data)) = ptr
				p.return_size = C.size_t(len(iv))
			default:
				ok = 0
			}
		case C.OSSL_CIPHER_PARAM_AEAD_TLS1_GET_IV_GEN, C.OSSL_CIPHER_PARAM_TLS_MAC, C.OSSL_CIPHER_PARAM_NUM:
			ok = 0 // not provided: fail rather than leave the buffer unwritten
		}
	}
	return C.int(ok)
}

//export gofips_cipher_set_ctx_params
func gofips_cipher_set_ctx_params(cctx C.uint64_t, params *C.OSSL_PARAM) C.int {
	return opGuard(func() C.int { return cipher_set_ctx_paramsOp(cctx, params) })
}

func cipher_set_ctx_paramsOp(cctx C.uint64_t, params *C.OSSL_PARAM) C.int {
	dbg("cipher_set_ctx_params cctx=%d", int64(cctx))
	ctx := regGetGcm(uint64(cctx))
	if ctx == nil || params == nil {
		return 0
	}
	ok := 1
	for i := 0; i < paramCount(params); i++ {
		p := paramAt(params, i)
		if p.key == nil {
			break
		}
		switch C.GoString(p.key) {
		case C.OSSL_CIPHER_PARAM_AEAD_TAG:
			// A full 16-byte tag, for a decrypt: the module's TLS 1.3 GCM
			// verifies only full tags, so a truncated one is refused.
			tag := append([]byte(nil), getOctetParam(p)...)
			set := false
			withLock(&ctx.mu, func() {
				if !ctx.enc && len(tag) == 16 {
					ctx.tagIn, set = tag, true
				}
			})
			if !set {
				return 0
			}
		case C.OSSL_CIPHER_PARAM_AEAD_TLS1_IV_FIXED:
			// TLS 1.2 GCM: the 4-byte implicit nonce part (RFC 5288).
			// Once per key: a second fixed IV, or a key that already
			// protected TLS 1.3 records, would restart a nonce sequence.
			fixed := append([]byte(nil), getOctetParam(p)...)
			set := false
			withLock(&ctx.mu, func() {
				if ctx.cbc || len(fixed) != 4 || len(ctx.key12) == 0 || ctx.tls12 != nil ||
					(ctx.aead != nil && (ctx.aead.used() || ctx.aead.isRetired())) {
					return
				}
				if ctx.aead != nil {
					ctx.aead.retire()
				}
				t, err := newTLS12GCM(ctx.key12, fixed)
				if err != nil {
					return
				}
				ctx.tls12, ctx.tlsAAD, set = t, nil, true
			})
			if !set {
				return 0
			}
		case C.OSSL_CIPHER_PARAM_AEAD_TLS1_AAD:
			// TLS 1.2 record header. Its length counts the explicit
			// nonce, and for a decrypt the tag too; the AAD carries the
			// data length (as the default provider's gcm_tls_init).
			aad := append([]byte(nil), getOctetParam(p)...)
			set := false
			withLock(&ctx.mu, func() {
				if ctx.tls12 == nil || len(aad) != tls12AADLen {
					return
				}
				l, over := int(binary.BigEndian.Uint16(aad[11:])), tls12ExplicitNonce
				if !ctx.enc {
					over += tls12Tag
				}
				if l < over {
					return
				}
				binary.BigEndian.PutUint16(aad[11:], uint16(l-over))
				ctx.tlsAAD, set = aad, true
			})
			if !set {
				return 0
			}
		case C.OSSL_CIPHER_PARAM_TLS_VERSION:
			// libssl sets this on every record cipher. TLS CBC record
			// mode (MAC-then-encrypt, padding removed provider side) is
			// not served, so a CBC ctx refuses it.
			if ctx.cbc {
				return 0
			}
		case C.OSSL_CIPHER_PARAM_TLS_MAC_SIZE:
			var m uint64
			if ctx.cbc || !getUintParam(p, &m) || m != 0 {
				return 0
			}
		case C.OSSL_CIPHER_PARAM_IVLEN:
			// tls13_set_crypto_state calls EVP_CTRL_AEAD_SET_IVLEN after
			// the keyless init; accept it when it matches our fixed 12.
			var want uint64
			if !getUintParam(p, &want) {
				return 0
			}
			if want != 12 {
				ok = 0
			}
		}
	}
	return C.int(ok)
}

//export gofips_cipher_gettable_params
func gofips_cipher_gettable_params(provctx *C.void) *C.OSSL_PARAM {
	_ = provctx
	return nil
}

//export gofips_cipher_gettable_ctx_params
func gofips_cipher_gettable_ctx_params(cctx C.uint64_t, provctx *C.void) *C.OSSL_PARAM {
	_ = cctx
	_ = provctx
	return nil
}

//export gofips_cipher_settable_ctx_params
func gofips_cipher_settable_ctx_params(cctx C.uint64_t, provctx *C.void) *C.OSSL_PARAM {
	_ = cctx
	_ = provctx
	return nil
}

func cipherParams(params *C.OSSL_PARAM, keylen, ivlen uint64) C.int {
	if params == nil {
		return 0
	}
	ok := 1
	for i := 0; i < paramCount(params); i++ {
		p := paramAt(params, i)
		if p.key == nil {
			break
		}
		switch C.GoString(p.key) {
		case C.OSSL_CIPHER_PARAM_KEYLEN:
			if !setUint(p, keylen) {
				ok = 0
			}
		case C.OSSL_CIPHER_PARAM_IVLEN:
			if !setUint(p, ivlen) {
				ok = 0
			}
		case C.OSSL_CIPHER_PARAM_MODE:
			if !setUint32(p, 6) { // EVP_CIPH_GCM_MODE (0x6)
				ok = 0
			}
		case C.OSSL_CIPHER_PARAM_AEAD:
			// The AEAD flag the SSL layer checks (ciphercommon.c sets it
			// from PROV_CIPHER_FLAG_AEAD).
			if !setUint(p, 1) {
				ok = 0
			}
		case C.OSSL_CIPHER_PARAM_AEAD_TAG:
			if !setUint(p, 16) {
				ok = 0
			}
		case C.OSSL_CIPHER_PARAM_AEAD_TAGLEN:
			// The TLS record layer (ssl_lib.c tls13_cipher,
			// EVP_CIPHER_CTX_tag_length) reads this from get_params
			// to size the record MAC buffer; answering it keeps
			// libssl from failing the record before EVP is reached.
			if !setUint(p, 16) {
				ok = 0
			}
		case C.OSSL_CIPHER_PARAM_CUSTOM_IV:
			if !setUint(p, 1) {
				ok = 0
			}
		case C.OSSL_CIPHER_PARAM_BLOCK_SIZE:
			// GCM is stream-like: EVP requires blocksize 1 (the
			// EVP_R_UPDATE_ERROR path fires on blocksize < 1,
			// verified against evp_enc.c).
			if !setUint(p, 1) {
				ok = 0
			}
		}
	}
	return C.int(ok)
}

// ---- EC key management (OSSL_OP_KEYMGMT, P-256 and P-384) ----

type ecKey struct {
	curve   *ecCurve // nil until known; cv() treats it as P-256
	priv    []byte   // big-endian scalar, curve size bytes
	pubX    []byte   // big-endian coordinates, curve size bytes
	pubY    []byte
	hasPriv bool
}

type ecCurve struct {
	name    string  // OpenSSL group name
	cname   *C.char // the same, for C callers
	size    int     // scalar and coordinate length in bytes
	ec      elliptic.Curve
	ecdh    ecdh.Curve
	maxSig  int // largest DER-encoded ECDSA signature
	secBits int
}

var (
	curveP256 = &ecCurve{"prime256v1", C.CString("prime256v1"), 32, elliptic.P256(), ecdh.P256(), 72, 128}
	curveP384 = &ecCurve{"secp384r1", C.CString("secp384r1"), 48, elliptic.P384(), ecdh.P384(), 104, 192}
)

func curveByName(name string) *ecCurve {
	switch name {
	case "prime256v1", "P-256", "secp256r1":
		return curveP256
	case "secp384r1", "P-384":
		return curveP384
	}
	return nil
}

func curveOf(c elliptic.Curve) *ecCurve {
	if c == elliptic.P384() {
		return curveP384
	}
	return curveP256
}

func (k *ecKey) cv() *ecCurve {
	if k.curve == nil {
		return curveP256
	}
	return k.curve
}

// point is the uncompressed encoding 0x04 || X || Y.
func (k *ecKey) point() []byte {
	n := k.cv().size
	b := make([]byte, 1+2*n)
	b[0] = 0x04
	copy(b[1:1+n], k.pubX)
	copy(b[1+n:], k.pubY)
	return b
}

// setPoint stores an uncompressed point. A key with no curve yet takes it
// from the point's length.
func (k *ecKey) setPoint(b []byte) bool {
	c := k.curve
	if c == nil {
		switch len(b) {
		case 65:
			c = curveP256
		case 97:
			c = curveP384
		default:
			return false
		}
	}
	n := c.size
	if len(b) != 1+2*n || b[0] != 0x04 {
		return false
	}
	k.curve = c
	k.pubX = append([]byte(nil), b[1:1+n]...)
	k.pubY = append([]byte(nil), b[1+n:]...)
	return true
}

//export gofips_keymgmt_new
func gofips_keymgmt_new(selection C.int, provctx *C.void) C.uint64_t {
	return handleGuard(func() C.uint64_t {
		_ = selection
		_ = provctx
		return C.uint64_t(regPut(&ecKey{}))
	})
}

//export gofips_keymgmt_free
func gofips_keymgmt_free(keydata C.uint64_t) {
	if key := regGetEcKey(uint64(keydata)); key != nil {
		clear(key.priv)
		key.priv = nil
		key.pubX, key.pubY = nil, nil
	}
	regDel(uint64(keydata))
}

//export gofips_keymgmt_load
func gofips_keymgmt_load(reference *C.uchar, referenceLen C.size_t, structure *C.char, selection C.int, provctx *C.void) C.uint64_t {
	return handleGuard(func() C.uint64_t {
		_ = reference
		_ = referenceLen
		_ = structure
		_ = selection
		_ = provctx
		return 0 // fail closed
	})
}

//export gofips_keymgmt_has
func gofips_keymgmt_has(keydata C.uint64_t, selection C.int) C.int {
	return opGuard(func() C.int { return keymgmt_hasOp(keydata, selection) })
}

func keymgmt_hasOp(keydata C.uint64_t, selection C.int) C.int {
	key := regGetEcKey(uint64(keydata))
	if key == nil {
		return 0
	}
	if selection&0x01 != 0 && !key.hasPriv { // OSSL_KEYMGMT_SELECT_PRIVATE_KEY
		return 0
	}
	if selection&0x02 != 0 && key.pubX == nil { // OSSL_KEYMGMT_SELECT_PUBLIC_KEY
		return 0
	}
	return 1
}

//export gofips_keymgmt_import
func gofips_keymgmt_import(keydata C.uint64_t, selection C.int, params *C.OSSL_PARAM) C.int {
	return opGuard(func() C.int { return keymgmtImport(keydata, selection, params) })
}

func keymgmtImport(keydata C.uint64_t, selection C.int, params *C.OSSL_PARAM) C.int {
	dbg("keymgmt_import keydata=%d selection=0x%x", int64(keydata), int(selection))
	key := regGetEcKey(uint64(keydata))
	if key == nil || params == nil {
		return 0
	}
	var pubBytes []byte
	for i := 0; i < paramCount(params); i++ {
		p := paramAt(params, i)
		if p.key == nil {
			break
		}
		switch C.GoString(p.key) {
		case C.OSSL_PKEY_PARAM_PRIV_KEY:
			if selection&0x01 != 0 {
				// Decode by declared type (an integer param holds the
				// BIGNUM's native-endian words, an octet string big-endian
				// bytes), normalize to the curve's length, then validate.
				if p.data_type == C.OSSL_PARAM_UNSIGNED_INTEGER || p.data_type == C.OSSL_PARAM_INTEGER {
					// BN words are little-endian on this platform:
					// reverse to big-endian scalar bytes.
					raw := getOctetParam(p)
					rev := make([]byte, len(raw))
					for i := range raw {
						rev[i] = raw[len(raw)-1-i]
					}
					key.priv = rev
				} else {
					key.priv = append([]byte(nil), getOctetParam(p)...)
				}
				key.hasPriv = true
				dbg("keymgmt_import: PRIV len=%d type=%d", len(key.priv), int(p.data_type))
				// The public point is not derived here. The
				// default provider does not expose a public part for a
				// priv-only import (get 'pub' fails) and deriving one
				// would diverge from it.
				// Priv-only imports stay priv-only; the scalar
				// orientation check below still validates against an
				// accompanying pub when one is imported.
				dbg("keymgmt_import: priv imported (%d bytes)", len(key.priv))
			}
		case C.OSSL_PKEY_PARAM_PUB_KEY:
			if selection&0x02 != 0 {
				pubBytes = append([]byte(nil), getOctetParam(p)...)
				dbg("keymgmt_import: PUB_KEY len=%d", len(pubBytes))
			}
		case C.OSSL_PKEY_PARAM_GROUP_NAME:
			var gn string
			if getUtf8Param(p, &gn) {
				if key.curve = curveByName(gn); key.curve == nil {
					return 0 // fail closed: P-256 and P-384 only
				}
			}
		case C.OSSL_PKEY_PARAM_EC_FIELD_TYPE, C.OSSL_PKEY_PARAM_EC_P, C.OSSL_PKEY_PARAM_EC_A,
			C.OSSL_PKEY_PARAM_EC_B, C.OSSL_PKEY_PARAM_EC_GENERATOR, C.OSSL_PKEY_PARAM_EC_ORDER,
			C.OSSL_PKEY_PARAM_EC_COFACTOR, C.OSSL_PKEY_PARAM_EC_SEED:
			// Explicit curve parameters: only named curves are served, and
			// get_params reports decoded-from-explicit as 0 on that basis.
			return 0
		case C.OSSL_PKEY_PARAM_EC_DECODED_FROM_EXPLICIT_PARAMS:
			// Set by the decoder for a key whose explicit parameters matched
			// a named curve. Refused, so libcrypto keeps it as a legacy key
			// that reports the flag and X509_verify_cert's check_curve
			// rejects the chain.
			var v uint64
			if !getUintParam(p, &v) || v != 0 {
				return 0
			}
		}
	}
	// The group may follow the point in the param list.
	if pubBytes != nil && !key.setPoint(pubBytes) {
		return 0
	}
	// Orientation validation: every
	// accepted import with a private scalar validates by arithmetic:
	// the scalar is normalized to canonical 32-byte big-endian and must
	// satisfy d*G == pub. Lengths other than 1..size bytes after
	// normalization are refused (an unpadded BIGNUM with a leading zero
	// arrives shorter and is padded to the curve size; anything longer is
	// invalid for the curve). A priv-only import without the public point
	// cannot be validated and is refused.
	if key.priv != nil {
		c := key.cv()
		// Zero every scalar copy not kept, and drop the private part on any
		// refusal.
		raw := key.priv
		var norm, rev []byte
		adopted := false
		defer func() {
			clear(raw)
			switch {
			case !adopted:
				clear(norm)
				clear(rev)
				key.priv, key.hasPriv = nil, false
			case &key.priv[0] == &norm[0]:
				clear(rev)
			default:
				clear(norm)
			}
		}()
		// Normalize: strip leading zeros (an unpadded BIGNUM may arrive
		// shorter than the curve size), then pad back to it.
		i := 0
		for i < len(key.priv) && key.priv[i] == 0 {
			i++
		}
		core := key.priv[i:]
		if len(core) == 0 || len(core) > c.size {
			dbg("keymgmt_import REFUSED: priv scalar length %d invalid for %s", len(core), c.name)
			return 0
		}
		norm = make([]byte, c.size)
		copy(norm[c.size-len(core):], core)
		if key.pubX == nil {
			dbg("keymgmt_import REFUSED: priv-only import without a public point cannot be validated (fail closed)")
			return 0
		}
		d := new(big.Int).SetBytes(norm)
		if d.Sign() <= 0 || d.Cmp(c.ec.Params().N) >= 0 {
			return 0
		}
		x, y := c.ec.ScalarBaseMult(d.Bytes())
		if x.Cmp(new(big.Int).SetBytes(key.pubX)) == 0 && y.Cmp(new(big.Int).SetBytes(key.pubY)) == 0 {
			key.priv, adopted = norm, true // canonical big-endian, validated
			return 1
		}
		// Try the byte-reversed orientation (the EC decoder's
		// little-endian handoff, observed on 4.0.3 and 3.5.x).
		rev = make([]byte, c.size)
		for j := range norm {
			rev[j] = norm[c.size-1-j]
		}
		dr := new(big.Int).SetBytes(rev)
		if dr.Sign() <= 0 || dr.Cmp(c.ec.Params().N) >= 0 {
			return 0
		}
		xr, yr := c.ec.ScalarBaseMult(dr.Bytes())
		if xr.Cmp(new(big.Int).SetBytes(key.pubX)) == 0 && yr.Cmp(new(big.Int).SetBytes(key.pubY)) == 0 {
			dbg("keymgmt_import: priv was little-endian; adopted reversed scalar")
			key.priv, adopted = rev, true
			return 1
		}
		dbg("keymgmt_import: priv/pub orientation mismatch, fail closed")
		return 0
	}
	return 1
}

//export gofips_keymgmt_export
func gofips_keymgmt_export(keydata C.uint64_t, selection C.int, cb *C.OSSL_CALLBACK, cbarg *C.void) C.int {
	return opGuard(func() C.int { return keymgmtExport(keydata, selection, cb, cbarg) })
}

func keymgmtExport(keydata C.uint64_t, selection C.int, cb *C.OSSL_CALLBACK, cbarg *C.void) C.int {
	dbg("keymgmt_export keydata=%d selection=0x%x", int64(keydata), int(selection))
	key := regGetEcKey(uint64(keydata))
	if key == nil || cb == nil {
		return 0
	}
	// The export params are built in C, so their keys are NUL-terminated.
	var pub []byte
	var priv []byte
	if selection&0x02 != 0 && key.pubX != nil {
		pub = key.point()
	}
	if selection&0x01 != 0 && key.priv != nil {
		// The export builder declares PRIV_KEY as UNSIGNED_INTEGER (the
		// type OSSL_PARAM_get_BN requires); integer params are read in
		// native byte order, so hand the scalar little-endian (the same
		// convention keymgmt_get_params uses for the BN path). The
		// canonical big-endian value is preserved through the BN.
		priv = make([]byte, len(key.priv))
		for i := range key.priv {
			priv[i] = key.priv[len(key.priv)-1-i]
		}
	}
	// The callback consumes the params synchronously. The buffers are C
	// copies, zeroed and freed when it returns, so no key copy outlives
	// the call.
	cbuf := func(b []byte) (*C.uchar, C.size_t, func()) {
		if b == nil {
			return nil, 0, func() {}
		}
		c := C.CBytes(b)
		return (*C.uchar)(c), C.size_t(len(b)), func() {
			clear(unsafe.Slice((*byte)(c), len(b)))
			C.free(c)
		}
	}
	pubPtr, pubLen, freePub := cbuf(pub)
	defer freePub()
	privPtr, privLen, freePriv := cbuf(priv)
	defer freePriv()
	clear(priv)
	paramsArr := (*C.OSSL_PARAM)(C.malloc(C.size_t(unsafe.Sizeof(C.OSSL_PARAM{})) * 4))
	defer C.free(unsafe.Pointer(paramsArr))
	n := C.gofips_build_ec_export_params(paramsArr, key.cv().cname, pubPtr, pubLen, privPtr, privLen)
	if n == 0 {
		return 0
	}
	if C.gofips_call_param_cb(cb, unsafe.Pointer(cbarg), paramsArr) == 0 {
		return 0
	}
	return 1
}

//export gofips_keymgmt_export_types
func gofips_keymgmt_export_types(selection C.int) *C.OSSL_PARAM {
	_ = selection
	return (*C.OSSL_PARAM)(unsafe.Pointer(&C.gofips_ec_export_types[0]))
}

//export gofips_keymgmt_import_types
func gofips_keymgmt_import_types(selection C.int) *C.OSSL_PARAM {
	_ = selection
	return (*C.OSSL_PARAM)(unsafe.Pointer(&C.gofips_ec_import_types[0]))
}

//export gofips_keymgmt_get_params
func gofips_keymgmt_get_params(keydata C.uint64_t, params *C.OSSL_PARAM) C.int {
	return opGuard(func() C.int { return keymgmt_get_paramsOp(keydata, params) })
}

func keymgmt_get_paramsOp(keydata C.uint64_t, params *C.OSSL_PARAM) C.int {
	key := regGetEcKey(uint64(keydata))
	if key == nil || params == nil {
		return 0
	}
	ok := 1
	for i := 0; i < paramCount(params); i++ {
		p := paramAt(params, i)
		if p.key == nil {
			break
		}
		switch C.GoString(p.key) {
		case C.OSSL_PKEY_PARAM_GROUP_NAME:
			if !setUtf8Ptr(p, key.cv().name) {
				ok = 0
			}
		case C.OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT:
			if !setUtf8Ptr(p, "uncompressed") {
				ok = 0
			}
		case C.OSSL_PKEY_PARAM_EC_DECODED_FROM_EXPLICIT_PARAMS:
			// X509_verify_cert's check_curve asks this of every EC key in
			// a chain of two or more and fails the chain on no answer.
			if !setIntParam(p, 0) {
				ok = 0
			}
		case C.OSSL_PKEY_PARAM_DEFAULT_DIGEST:
			if !setUtf8Ptr(p, "SHA256") {
				ok = 0
			}
		case C.OSSL_PKEY_PARAM_MAX_SIZE:
			if !setUint32(p, uint64(key.cv().maxSig)) {
				ok = 0
			}
		case C.OSSL_PKEY_PARAM_BITS:
			if !setUint32(p, uint64(key.cv().size*8)) {
				ok = 0
			}
		case C.OSSL_PKEY_PARAM_SECURITY_BITS:
			if !setUint32(p, uint64(key.cv().secBits)) {
				ok = 0
			}
		case C.OSSL_PKEY_PARAM_PUB_KEY, C.OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY:
			// Uncompressed point: 0x04 || X || Y (EVP_PKEY_get1_encoded_public_key
			// reads ENCODED_PUBLIC_KEY, the TLS key-share path).
			key := regGetEcKey(uint64(keydata))
			if key == nil || key.pubX == nil {
				ok = 0
				break
			}
			pub := key.point()
			// An undersized caller buffer is an error (rc=0 with
			// return_size = needed), matching the default provider; a
			// success with an untouched buffer leaks nothing but lies.
			if !setOctet(p, pub) {
				ok = 0
			}
		case C.OSSL_PKEY_PARAM_PRIV_KEY:
			key := regGetEcKey(uint64(keydata))
			if key == nil || key.priv == nil {
				ok = 0
				break
			}
			// The exported scalar must be the canonical
			// big-endian private value with d*G == pub. key.priv is
			// stored big-endian (imports adopt the orientation whose
			// ScalarBaseMult equals the pub; keygen fills from
			// priv.D.FillBytes), so a straight octet copy is canonical.
			// The assertion here guards the invariant: if the stored
			// scalar fails d*G == pub, the export refuses rather than
			// handing out a byte-swapped scalar.
			d := new(big.Int).SetBytes(key.priv)
			if key.pubX != nil {
				x, y := key.cv().ec.ScalarBaseMult(d.Bytes())
				if x.Cmp(new(big.Int).SetBytes(key.pubX)) != 0 || y.Cmp(new(big.Int).SetBytes(key.pubY)) != 0 {
					dbg("keymgmt_get_params REFUSED: priv scalar fails d*G == pub (canonical export guard)")
					ok = 0
					break
				}
			}
			if p.data_type == C.OSSL_PARAM_UNSIGNED_INTEGER {
				// EVP_PKEY_get_bn_param builds an UNSIGNED_INTEGER param;
				// OSSL_PARAM_get_BN reads that buffer in native byte
				// order (little-endian on x86), so the canonical
				// big-endian octet written raw would come back as the
				// byte-reversed BIGNUM. Write the
				// scalar little-endian for this param type so the BN
				// equals the canonical value.
				le := make([]byte, len(key.priv))
				for i := range le {
					le[i] = key.priv[len(key.priv)-1-i]
				}
				defer clear(le)
				// As the default provider: a NULL buffer is a size query
				// (write nothing); a short buffer fails; otherwise write the
				// scalar and shrink data_size to it (OSSL_PARAM_get_BN
				// trusts data_size).
				if p.data == nil {
					p.return_size = C.size_t(len(le))
					break
				}
				if int(p.data_size) < len(le) {
					// An undersized non-NULL buffer is an error
					// (needed size reported, nothing written),
					// matching default.
					p.return_size = C.size_t(len(le))
					ok = 0
					break
				}
				copy(unsafe.Slice((*byte)(unsafe.Pointer(p.data)), int(p.data_size)), le)
				p.data_size = C.size_t(len(le))
				p.return_size = C.size_t(len(le))
			} else {
				// Same contract on the octet path.
				if !setOctet(p, key.priv) {
					ok = 0
				}
			}
		}
	}
	return C.int(ok)
}

//export gofips_keymgmt_gettable_params
func gofips_keymgmt_gettable_params(keydata C.uint64_t) *C.OSSL_PARAM {
	_ = keydata
	return (*C.OSSL_PARAM)(unsafe.Pointer(&C.gofips_ec_keymgmt_params[0]))
}

//export gofips_keymgmt_set_params
func gofips_keymgmt_set_params(keydata C.uint64_t, params *C.OSSL_PARAM) C.int {
	return opGuard(func() C.int { return keymgmt_set_paramsOp(keydata, params) })
}

func keymgmt_set_paramsOp(keydata C.uint64_t, params *C.OSSL_PARAM) C.int {
	key := regGetEcKey(uint64(keydata))
	if key == nil || params == nil {
		return 0
	}
	// TLS 1.3 key-share import: EVP_PKEY_set1_encoded_public_key sets
	// ENCODED_PUBLIC_KEY (uncompressed point) on the peer key.
	ok := 1
	for i := 0; i < paramCount(params); i++ {
		p := paramAt(params, i)
		if p.key == nil {
			break
		}
		switch C.GoString(p.key) {
		case C.OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY:
			if !key.setPoint(getOctetParam(p)) {
				ok = 0
			}
		default:
			ok = 0 // fail closed on unknown set params
		}
	}
	return C.int(ok)
}

//export gofips_keymgmt_settable_params
func gofips_keymgmt_settable_params(keydata C.uint64_t) *C.OSSL_PARAM {
	_ = keydata
	return nil
}

//export gofips_keymgmt_match
func gofips_keymgmt_match(keydata1 C.uint64_t, keydata2 C.uint64_t, selection C.int) C.int {
	return opGuard(func() C.int { return keymgmt_matchOp(keydata1, keydata2, selection) })
}

func keymgmt_matchOp(keydata1 C.uint64_t, keydata2 C.uint64_t, selection C.int) C.int {
	// Used by X509_check_private_key (cert pub vs key pub) when one side
	// is a provider key. Compare the requested components.
	k1 := regGetEcKey(uint64(keydata1))
	k2 := regGetEcKey(uint64(keydata2))
	if k1 == nil || k2 == nil || k1.cv() != k2.cv() {
		return 0
	}
	if selection&0x02 != 0 { // public
		if k1.pubX == nil || k2.pubX == nil {
			return 0
		}
		if !bytesEqual(k1.pubX, k2.pubX) || !bytesEqual(k1.pubY, k2.pubY) {
			return 0
		}
	}
	if selection&0x01 != 0 { // private
		if k1.priv == nil || k2.priv == nil {
			return 0
		}
		if !bytesEqual(k1.priv, k2.priv) {
			return 0
		}
	}
	return 1
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

//export gofips_keymgmt_validate
func gofips_keymgmt_validate(keydata C.uint64_t, selection C.int, checkType C.int) C.int {
	return opGuard(func() C.int { return keymgmt_validateOp(keydata, selection, checkType) })
}

func keymgmt_validateOp(keydata C.uint64_t, selection C.int, checkType C.int) C.int {
	key := regGetEcKey(uint64(keydata))
	// A key with no point (nothing imported or generated) is not valid.
	if key == nil || key.curve == nil || key.pubX == nil {
		return 0
	}
	c := key.cv()
	if key.pubX != nil {
		x := new(big.Int).SetBytes(key.pubX)
		y := new(big.Int).SetBytes(key.pubY)
		if !c.ec.IsOnCurve(x, y) {
			return 0
		}
		if selection&0x01 != 0 && key.priv != nil {
			px, py := c.ec.ScalarBaseMult(key.priv)
			if px.Cmp(x) != 0 || py.Cmp(y) != 0 {
				return 0
			}
		}
	}
	return 1
}

//export gofips_keymgmt_query_operation_name
func gofips_keymgmt_query_operation_name(operationID C.int) *C.char {
	// The names are static; return a pinned pointer.
	switch operationID {
	case C.OSSL_OP_KEYEXCH:
		return queryNameECDH
	case C.OSSL_OP_SIGNATURE:
		return queryNameECDSA
	}
	return nil
}

var queryNameECDH = C.CString("ECDH")
var queryNameECDSA = C.CString("ECDSA")

//export gofips_keymgmt_gen_init
func gofips_keymgmt_gen_init(provctx *C.void, selection C.int, params *C.OSSL_PARAM) C.uint64_t {
	return handleGuard(func() C.uint64_t {
		_ = provctx
		_ = selection
		_ = params
		return C.uint64_t(regPut(&ecKey{}))
	})
}

//export gofips_keymgmt_gen_set_template
func gofips_keymgmt_gen_set_template(genctx C.uint64_t, templ C.uint64_t) C.int {
	return opGuard(func() C.int { return keymgmt_gen_set_templateOp(genctx, templ) })
}

func keymgmt_gen_set_templateOp(genctx C.uint64_t, templ C.uint64_t) C.int {
	g, t := regGetEcKey(uint64(genctx)), regGetEcKey(uint64(templ))
	if g == nil || t == nil {
		return 0
	}
	g.curve = t.curve
	return 1
}

//export gofips_keymgmt_gen_set_params
func gofips_keymgmt_gen_set_params(genctx C.uint64_t, params *C.OSSL_PARAM) C.int {
	return opGuard(func() C.int { return keymgmt_gen_set_paramsOp(genctx, params) })
}

func keymgmt_gen_set_paramsOp(genctx C.uint64_t, params *C.OSSL_PARAM) C.int {
	g := regGetEcKey(uint64(genctx))
	if g == nil {
		return 0
	}
	ok := 1
	for i := 0; i < paramCount(params); i++ {
		p := paramAt(params, i)
		if p.key == nil {
			break
		}
		switch C.GoString(p.key) {
		case C.OSSL_PKEY_PARAM_GROUP_NAME:
			var gn string
			if getUtf8Param(p, &gn) {
				if c := curveByName(gn); c != nil {
					g.curve = c
				} else {
					ok = 0 // fail closed
				}
			}
		}
	}
	return C.int(ok)
}

//export gofips_keymgmt_gen_settable_params
func gofips_keymgmt_gen_settable_params(genctx C.uint64_t, provctx *C.void) *C.OSSL_PARAM {
	_ = genctx
	_ = provctx
	return (*C.OSSL_PARAM)(unsafe.Pointer(&C.gofips_ec_keymgmt_params[0]))
}

//export gofips_keymgmt_gen_get_params
func gofips_keymgmt_gen_get_params(genctx C.uint64_t, params *C.OSSL_PARAM) C.int {
	return opGuard(func() C.int { return keymgmt_gen_get_paramsOp(genctx, params) })
}

func keymgmt_gen_get_paramsOp(genctx C.uint64_t, params *C.OSSL_PARAM) C.int {
	_ = genctx
	_ = params
	return 1
}

//export gofips_keymgmt_gen_gettable_params
func gofips_keymgmt_gen_gettable_params(genctx C.uint64_t, provctx *C.void) *C.OSSL_PARAM {
	_ = genctx
	_ = provctx
	return nil
}

//export gofips_keymgmt_gen
func gofips_keymgmt_gen(genctx C.uint64_t, cb *C.OSSL_CALLBACK, cbarg *C.void) C.uint64_t {
	return handleGuard(func() C.uint64_t {
		_ = cb
		_ = cbarg
		g := regGetEcKey(uint64(genctx))
		if g == nil || g.curve == nil {
			return 0 // no group set, as the default provider
		}
		c := g.curve
		priv, err := ecdsa.GenerateKey(c.ec, cryptorand.Reader)
		if err != nil {
			return 0
		}
		dbg("keymgmt_gen: %s key generated", c.name)
		key := &ecKey{
			curve:   c,
			priv:    priv.D.FillBytes(make([]byte, c.size)),
			pubX:    priv.X.FillBytes(make([]byte, c.size)),
			pubY:    priv.Y.FillBytes(make([]byte, c.size)),
			hasPriv: true,
		}
		return C.uint64_t(regPut(key))
	})
}

//export gofips_keymgmt_gen_cleanup
func gofips_keymgmt_gen_cleanup(genctx C.uint64_t) {
	// gen_init registered the genctx; remove it.
	regDel(uint64(genctx))
}

//export gofips_keymgmt_dup
func gofips_keymgmt_dup(keydata C.uint64_t, selection C.int) C.uint64_t {
	return handleGuard(func() C.uint64_t {
		src := regGetEcKey(uint64(keydata))
		if src == nil {
			return 0
		}
		// Deep, full copy: freeing the dup zeroes its own storage, and callers
		// dup with a narrow selection yet use the whole key (libssl signs with
		// a pub-only dup).
		key := &ecKey{
			curve:   src.curve,
			priv:    append([]byte(nil), src.priv...),
			hasPriv: src.hasPriv,
			pubX:    append([]byte(nil), src.pubX...),
			pubY:    append([]byte(nil), src.pubY...),
		}
		return C.uint64_t(regPut(key))
	})
}

// ---- ECDH key exchange (OSSL_OP_KEYEXCH, P-256 and P-384) ----

type ecdhCtx struct {
	mu   sync.Mutex
	key  *ecKey
	peer *ecKey
}

//export gofips_keyexch_newctx
func gofips_keyexch_newctx(provctx *C.void) C.uint64_t {
	return handleGuard(func() C.uint64_t {
		dbg("keyexch_newctx")
		_ = provctx
		return C.uint64_t(regPut(&ecdhCtx{}))
	})
}

//export gofips_keyexch_freectx
func gofips_keyexch_freectx(kctx C.uint64_t) {
	regDel(uint64(kctx))
}

//export gofips_keyexch_init
func gofips_keyexch_init(kctx C.uint64_t, provkey C.uint64_t, params *C.OSSL_PARAM) C.int {
	return opGuard(func() C.int { return keyexch_initOp(kctx, provkey, params) })
}

func keyexch_initOp(kctx C.uint64_t, provkey C.uint64_t, params *C.OSSL_PARAM) C.int {
	dbg("keyexch_init key=%v", provkey != 0)
	_ = params
	ctx := regGetEcdh(uint64(kctx))
	key := regGetEcKey(uint64(provkey))
	if ctx == nil || key == nil {
		return 0
	}
	withLock(&ctx.mu, func() {
		ctx.key = key
	})
	return 1
}

//export gofips_keyexch_set_peer
func gofips_keyexch_set_peer(kctx C.uint64_t, provkey C.uint64_t) C.int {
	return opGuard(func() C.int { return keyexch_set_peerOp(kctx, provkey) })
}

func keyexch_set_peerOp(kctx C.uint64_t, provkey C.uint64_t) C.int {
	dbg("keyexch_set_peer key=%v", provkey != 0)
	ctx := regGetEcdh(uint64(kctx))
	peer := regGetEcKey(uint64(provkey))
	if ctx == nil || peer == nil {
		return 0
	}
	withLock(&ctx.mu, func() {
		ctx.peer = peer
	})
	return 1
}

//export gofips_keyexch_derive
func gofips_keyexch_derive(kctx C.uint64_t, secret *C.uchar, secretlen *C.size_t, outlen C.size_t) C.int {
	return opGuard(func() C.int { return keyexchDerive(kctx, secret, secretlen, outlen) })
}

func keyexchDerive(kctx C.uint64_t, secret *C.uchar, secretlen *C.size_t, outlen C.size_t) C.int {
	dbg("keyexch_derive kctx=%d outlen=%d", int64(kctx), int(outlen))
	ctx := regGetEcdh(uint64(kctx))
	if ctx == nil || secretlen == nil {
		dbg("keyexch_derive: ctx/secretlen nil")
		return 0
	}
	ctx.mu.Lock()
	key, peer := ctx.key, ctx.peer
	ctx.mu.Unlock()
	if key == nil || peer == nil || key.priv == nil || peer.pubX == nil {
		dbg("keyexch_derive: key=%v peer=%v priv=%v pubx=%v",
			key != nil, peer != nil,
			key != nil && key.priv != nil,
			peer != nil && peer.pubX != nil)
		return 0
	}
	if key.cv() != peer.cv() {
		return 0
	}
	if debugEnabled {
		dbg("keyexch_derive INPUTS priv=%x peerpub=%x", key.priv, peer.point())
	}
	// ECDH via the crypto/ecdh package (the Go Cryptographic Module's
	// ECDH in FIPS mode).
	c := key.cv()
	peerKey, err := c.ecdh.NewPublicKey(peer.point())
	if err != nil {
		return 0
	}
	privKey, err := c.ecdh.NewPrivateKey(new(big.Int).SetBytes(key.priv).FillBytes(make([]byte, c.size)))
	if err != nil {
		return 0
	}
	secretBytes, err := privKey.ECDH(peerKey)
	if err != nil {
		dbg("keyexch_derive: ECDH failed: %v", err)
		return 0
	}
	if debugEnabled {
		dbg("keyexch_derive OUTPUT secret=%x", secretBytes)
	}
	if int(outlen) < len(secretBytes) {
		// Size probe (secret==NULL, outlen==0) or too-small buffer:
		// report the needed length. EVP_PKEY_derive(NULL, &len) expects
		// return 1 with *secretlen set; a non-null too-small buffer is
		// a real error.
		*secretlen = C.size_t(len(secretBytes))
		if secret == nil || outlen == 0 {
			return 1
		}
		return 0
	}
	copy(unsafe.Slice((*byte)(unsafe.Pointer(secret)), len(secretBytes)), secretBytes)
	*secretlen = C.size_t(len(secretBytes))
	recordOp("ecdh")
	return 1
}

//export gofips_keyexch_set_ctx_params
func gofips_keyexch_set_ctx_params(kctx C.uint64_t, params *C.OSSL_PARAM) C.int {
	return opGuard(func() C.int { return keyexch_set_ctx_paramsOp(kctx, params) })
}

func keyexch_set_ctx_paramsOp(kctx C.uint64_t, params *C.OSSL_PARAM) C.int {
	_ = kctx
	_ = params
	return 0 // fail closed
}

//export gofips_keyexch_get_ctx_params
func gofips_keyexch_get_ctx_params(kctx C.uint64_t, params *C.OSSL_PARAM) C.int {
	return opGuard(func() C.int { return keyexch_get_ctx_paramsOp(kctx, params) })
}

func keyexch_get_ctx_paramsOp(kctx C.uint64_t, params *C.OSSL_PARAM) C.int {
	_ = kctx
	_ = params
	return 1
}

//export gofips_keyexch_settable_ctx_params
func gofips_keyexch_settable_ctx_params(kctx C.uint64_t, provctx *C.void) *C.OSSL_PARAM {
	_ = kctx
	_ = provctx
	return nil
}

//export gofips_keyexch_gettable_ctx_params
func gofips_keyexch_gettable_ctx_params(kctx C.uint64_t, provctx *C.void) *C.OSSL_PARAM {
	_ = kctx
	_ = provctx
	return nil
}

//export gofips_keyexch_dupctx
func gofips_keyexch_dupctx(kctx C.uint64_t) C.uint64_t {
	return handleGuard(func() C.uint64_t {
		s := regGetEcdh(uint64(kctx))
		if s == nil {
			return 0
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		return C.uint64_t(regPut(&ecdhCtx{key: s.key, peer: s.peer}))
	})
}

// ---- ECDSA signatures (OSSL_OP_SIGNATURE, P-256 and P-384; SHA-256/384/512) ----

type sigCtx struct {
	mu  sync.Mutex
	key *ecKey
	md  cryptoc.Hash
	h   hash.Hash // streaming digest_sign/verify state
}

//export gofips_sig_newctx
func gofips_sig_newctx(provctx *C.void, propq *C.char) C.uint64_t {
	return handleGuard(func() C.uint64_t {
		_ = provctx
		_ = propq
		return C.uint64_t(regPut(&sigCtx{}))
	})
}

//export gofips_sig_freectx
func gofips_sig_freectx(sctx C.uint64_t) {
	regDel(uint64(sctx))
}

//export gofips_sig_dupctx
func gofips_sig_dupctx(sctx C.uint64_t) C.uint64_t {
	return handleGuard(func() C.uint64_t {
		s := regGetSig(uint64(sctx))
		if s == nil {
			return 0
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		d := &sigCtx{key: s.key, md: s.md}
		if s.h != nil {
			if d.h = hashClone(s.h); d.h == nil {
				return 0
			}
		}
		return C.uint64_t(regPut(d))
	})
}

func sigKey(sctx C.uint64_t, provkey C.uint64_t) (*sigCtx, *ecKey) {
	ctx := regGetSig(uint64(sctx))
	key := regGetEcKey(uint64(provkey))
	if ctx == nil || key == nil {
		return nil, nil
	}
	return ctx, key
}

func sigMDFromName(name string) cryptoc.Hash {
	switch name {
	case "sha256", "SHA2-256", "SHA256":
		return cryptoc.SHA256
	case "sha384", "SHA2-384", "SHA384":
		return cryptoc.SHA384
	case "sha512", "SHA2-512", "SHA512":
		return cryptoc.SHA512
	}
	return 0 // fail closed
}

func sigHash(md cryptoc.Hash) hash.Hash {
	switch md {
	case cryptoc.SHA256:
		return sha256.New()
	case cryptoc.SHA384:
		return sha512.New384()
	case cryptoc.SHA512:
		return sha512.New()
	}
	return nil
}

func ecdsaPriv(key *ecKey) *ecdsa.PrivateKey {
	return &ecdsa.PrivateKey{PublicKey: *ecdsaPub(key), D: new(big.Int).SetBytes(key.priv)}
}

func ecdsaPub(key *ecKey) *ecdsa.PublicKey {
	return &ecdsa.PublicKey{
		Curve: key.cv().ec,
		X:     new(big.Int).SetBytes(key.pubX),
		Y:     new(big.Int).SetBytes(key.pubY),
	}
}

// ecdsaVerifyDER is the verdict for every verify path: the DER pre-check
// rejects structural garbage, then ecdsa.VerifyASN1 decides.
func ecdsaVerifyDER(key *ecKey, digest []byte, sig *C.uchar, siglen C.size_t) C.int {
	der := unsafe.Slice((*byte)(unsafe.Pointer(sig)), int(siglen))
	if _, _, err := decodeECDSASigDER(der); err != nil {
		return 0
	}
	if digest == nil || !ecdsa.VerifyASN1(ecdsaPub(key), digest, der) {
		return 0
	}
	recordOp("ecdsa")
	return 1
}

//export gofips_sig_sign_init
func gofips_sig_sign_init(sctx C.uint64_t, provkey C.uint64_t, params *C.OSSL_PARAM) C.int {
	return opGuard(func() C.int { return sig_sign_initOp(sctx, provkey, params) })
}

func sig_sign_initOp(sctx C.uint64_t, provkey C.uint64_t, params *C.OSSL_PARAM) C.int {
	_ = params
	ctx, key := sigKey(sctx, provkey)
	if ctx == nil {
		return 0
	}
	withLock(&ctx.mu, func() {
		ctx.key, ctx.md, ctx.h = key, 0, nil
	})
	return 1
}

//export gofips_sig_sign
func gofips_sig_sign(sctx C.uint64_t, sig *C.uchar, siglen *C.size_t, sigsize C.size_t, tbs *C.uchar, tbslen C.size_t) C.int {
	return opGuard(func() C.int { return sigSign(sctx, sig, siglen, sigsize, tbs, tbslen) })
}

func sigSign(sctx C.uint64_t, sig *C.uchar, siglen *C.size_t, sigsize C.size_t, tbs *C.uchar, tbslen C.size_t) C.int {
	ctx := regGetSig(uint64(sctx))
	if ctx == nil || siglen == nil || tbs == nil {
		return 0
	}
	ctx.mu.Lock()
	key, md := ctx.key, ctx.md
	ctx.mu.Unlock()
	if key == nil || key.priv == nil {
		return 0
	}
	h := preHashed(md, tbs, tbslen)
	if h == nil {
		return 0
	}
	return ecdsaSignInto(ecdsaPriv(key), h, sig, siglen, sigsize)
}

//export gofips_sig_verify_init
func gofips_sig_verify_init(sctx C.uint64_t, provkey C.uint64_t, params *C.OSSL_PARAM) C.int {
	return opGuard(func() C.int { return sig_verify_initOp(sctx, provkey, params) })
}

func sig_verify_initOp(sctx C.uint64_t, provkey C.uint64_t, params *C.OSSL_PARAM) C.int {
	_ = params
	ctx, key := sigKey(sctx, provkey)
	if ctx == nil {
		return 0
	}
	withLock(&ctx.mu, func() {
		ctx.key, ctx.md, ctx.h = key, 0, nil
	})
	return 1
}

//export gofips_sig_verify
func gofips_sig_verify(sctx C.uint64_t, sig *C.uchar, siglen C.size_t, tbs *C.uchar, tbslen C.size_t) C.int {
	return opGuard(func() C.int { return sigVerify(sctx, sig, siglen, tbs, tbslen) })
}

func sigVerify(sctx C.uint64_t, sig *C.uchar, siglen C.size_t, tbs *C.uchar, tbslen C.size_t) C.int {
	ctx := regGetSig(uint64(sctx))
	if ctx == nil || sig == nil || tbs == nil {
		return 0
	}
	ctx.mu.Lock()
	key, md := ctx.key, ctx.md
	ctx.mu.Unlock()
	if key == nil || key.pubX == nil {
		return 0
	}
	return ecdsaVerifyDER(key, preHashed(md, tbs, tbslen), sig, siglen)
}

// preHashed is tbs for EVP_PKEY_sign/verify, which pass a digest. It needs
// the digest named (no set_ctx_params path sets one, so this fails closed)
// and of that digest's length.
func preHashed(md cryptoc.Hash, tbs *C.uchar, tbslen C.size_t) []byte {
	if md == 0 || tbs == nil || int(tbslen) != md.Size() {
		return nil
	}
	return append([]byte(nil), unsafe.Slice((*byte)(unsafe.Pointer(tbs)), int(tbslen))...)
}

//export gofips_sig_digest_sign_init
func gofips_sig_digest_sign_init(sctx C.uint64_t, mdname *C.char, provkey C.uint64_t, params *C.OSSL_PARAM) C.int {
	return opGuard(func() C.int { return sig_digest_sign_initOp(sctx, mdname, provkey, params) })
}

func sig_digest_sign_initOp(sctx C.uint64_t, mdname *C.char, provkey C.uint64_t, params *C.OSSL_PARAM) C.int {
	dbg("sig_digest_sign_init md=%s key=%v", C.GoString(mdname), provkey != 0)
	_ = params
	ctx, key := sigKey(sctx, provkey)
	if ctx == nil {
		return 0
	}
	md := sigMDFromName(C.GoString(mdname))
	if md == 0 {
		return 0 // fail closed
	}
	withLock(&ctx.mu, func() {
		ctx.key, ctx.md, ctx.h = key, md, sigHash(md)
	})
	return 1
}

//export gofips_sig_digest_sign
func gofips_sig_digest_sign(sctx C.uint64_t, sigret *C.uchar, siglen *C.size_t, sigsize C.size_t, tbs *C.uchar, tbslen C.size_t) C.int {
	return opGuard(func() C.int { return sigDigestSign(sctx, sigret, siglen, sigsize, tbs, tbslen) })
}

func sigDigestSign(sctx C.uint64_t, sigret *C.uchar, siglen *C.size_t, sigsize C.size_t, tbs *C.uchar, tbslen C.size_t) C.int {
	dbg("sig_digest_sign sctx=%d sigsize=%d tbslen=%d", int64(sctx), int(sigsize), int(tbslen))
	ctx := regGetSig(uint64(sctx))
	if ctx == nil || siglen == nil || tbs == nil {
		dbg("sig_digest_sign: ctx/siglen/tbs nil")
		return 0
	}
	ctx.mu.Lock()
	key, md := ctx.key, ctx.md
	ctx.mu.Unlock()
	if key == nil || key.priv == nil {
		dbg("sig_digest_sign: key nil or priv missing")
		return 0
	}
	privKey := ecdsaPriv(key)
	digest := hashFor(md, tbs, int(tbslen))
	if digest == nil {
		dbg("sig_digest_sign: no hash for md")
		return 0
	}
	// digest_sign semantics: tbs is the raw data; the provider hashes it
	// with the MD from digest_sign_init, as verify and every OpenSSL
	// peer do.
	raw := unsafe.Slice((*byte)(unsafe.Pointer(tbs)), int(tbslen))
	dbg("sig_digest_sign raw_tbs=%x", raw)
	rc := ecdsaSignInto(privKey, digest, sigret, siglen, sigsize)
	if rc == 1 && sigret != nil {
		dbg("sig_digest_sign OK digest=%x pubX=%x pubY=%x", digest, key.pubX, key.pubY)
	}
	return rc
}

//export gofips_sig_digest_verify_init
func gofips_sig_digest_verify_init(sctx C.uint64_t, mdname *C.char, provkey C.uint64_t, params *C.OSSL_PARAM) C.int {
	return opGuard(func() C.int { return sig_digest_verify_initOp(sctx, mdname, provkey, params) })
}

func sig_digest_verify_initOp(sctx C.uint64_t, mdname *C.char, provkey C.uint64_t, params *C.OSSL_PARAM) C.int {
	dbg("sig_digest_verify_init md=%s key=%v", C.GoString(mdname), provkey != 0)
	_ = params
	ctx, key := sigKey(sctx, provkey)
	if ctx == nil {
		dbg("sig_digest_verify_init: ctx/key lookup failed")
		return 0
	}
	md := sigMDFromName(C.GoString(mdname))
	if md == 0 {
		return 0
	}
	withLock(&ctx.mu, func() {
		ctx.key, ctx.md, ctx.h = key, md, sigHash(md)
	})
	return 1
}

//export gofips_sig_digest_verify
func gofips_sig_digest_verify(sctx C.uint64_t, sig *C.uchar, siglen C.size_t, tbs *C.uchar, tbslen C.size_t) C.int {
	return opGuard(func() C.int { return sigDigestVerify(sctx, sig, siglen, tbs, tbslen) })
}

func sigDigestVerify(sctx C.uint64_t, sig *C.uchar, siglen C.size_t, tbs *C.uchar, tbslen C.size_t) C.int {
	dbg("sig_digest_verify sctx=%d siglen=%d tbslen=%d", int64(sctx), int(siglen), int(tbslen))
	ctx := regGetSig(uint64(sctx))
	if ctx == nil || sig == nil || tbs == nil {
		dbg("sig_digest_verify: ctx/sig/tbs nil")
		return 0
	}
	ctx.mu.Lock()
	key, md := ctx.key, ctx.md
	ctx.mu.Unlock()
	if key == nil || key.pubX == nil {
		dbg("sig_digest_verify: key nil or pub missing")
		return 0
	}
	return ecdsaVerifyDER(key, hashFor(md, tbs, int(tbslen)), sig, siglen)
}

// Streaming digest_sign/verify (EVP_DigestSignUpdate/Final), the shape
// node:crypto and WebCrypto use; TLS uses the one-shot ops above.

//export gofips_sig_digest_sign_update
func gofips_sig_digest_sign_update(sctx C.uint64_t, data *C.uchar, datalen C.size_t) C.int {
	return opGuard(func() C.int { return sigDigestUpdate(sctx, data, datalen) })
}

//export gofips_sig_digest_verify_update
func gofips_sig_digest_verify_update(sctx C.uint64_t, data *C.uchar, datalen C.size_t) C.int {
	return opGuard(func() C.int { return sigDigestUpdate(sctx, data, datalen) })
}

func sigDigestUpdate(sctx C.uint64_t, data *C.uchar, datalen C.size_t) C.int {
	ctx := regGetSig(uint64(sctx))
	if ctx == nil || (data == nil && datalen > 0) {
		return 0
	}
	ctx.mu.Lock()
	defer ctx.mu.Unlock()
	if ctx.h == nil {
		return 0
	}
	if datalen > 0 {
		ctx.h.Write(unsafe.Slice((*byte)(unsafe.Pointer(data)), int(datalen)))
	}
	return 1
}

// sigDigest returns the digest so far; Sum leaves the state intact, so a
// size query followed by the real final call signs the same message.
func sigDigest(sctx C.uint64_t) (*ecKey, []byte) {
	ctx := regGetSig(uint64(sctx))
	if ctx == nil {
		return nil, nil
	}
	ctx.mu.Lock()
	defer ctx.mu.Unlock()
	if ctx.h == nil || ctx.key == nil {
		return nil, nil
	}
	return ctx.key, ctx.h.Sum(nil)
}

//export gofips_sig_digest_sign_final
func gofips_sig_digest_sign_final(sctx C.uint64_t, sig *C.uchar, siglen *C.size_t, sigsize C.size_t) C.int {
	return opGuard(func() C.int {
		key, digest := sigDigest(sctx)
		if key == nil || key.priv == nil || siglen == nil {
			return 0
		}
		return ecdsaSignInto(ecdsaPriv(key), digest, sig, siglen, sigsize)
	})
}

//export gofips_sig_digest_verify_final
func gofips_sig_digest_verify_final(sctx C.uint64_t, sig *C.uchar, siglen C.size_t) C.int {
	return opGuard(func() C.int {
		key, digest := sigDigest(sctx)
		if key == nil || key.pubX == nil || sig == nil {
			return 0
		}
		return ecdsaVerifyDER(key, digest, sig, siglen)
	})
}

//export gofips_sig_get_ctx_params
func gofips_sig_get_ctx_params(sctx C.uint64_t, params *C.OSSL_PARAM) C.int {
	return opGuard(func() C.int { return sig_get_ctx_paramsOp(sctx, params) })
}

func sig_get_ctx_paramsOp(sctx C.uint64_t, params *C.OSSL_PARAM) C.int {
	_ = sctx
	_ = params
	return 1
}

//export gofips_sig_set_ctx_params
func gofips_sig_set_ctx_params(sctx C.uint64_t, params *C.OSSL_PARAM) C.int {
	return opGuard(func() C.int { return sig_set_ctx_paramsOp(sctx, params) })
}

func sig_set_ctx_paramsOp(sctx C.uint64_t, params *C.OSSL_PARAM) C.int {
	_ = sctx
	_ = params
	return 0 // fail closed
}

//export gofips_sig_gettable_ctx_params
func gofips_sig_gettable_ctx_params(sctx C.uint64_t, provctx *C.void) *C.OSSL_PARAM {
	_ = sctx
	_ = provctx
	return nil
}

//export gofips_sig_settable_ctx_params
func gofips_sig_settable_ctx_params(sctx C.uint64_t, provctx *C.void) *C.OSSL_PARAM {
	_ = sctx
	_ = provctx
	return nil
}

// ---- helpers ----

func hashFor(md cryptoc.Hash, tbs *C.uchar, tbslen int) []byte {
	b := unsafe.Slice((*byte)(unsafe.Pointer(tbs)), tbslen)
	switch md {
	case cryptoc.SHA256:
		s := sha256.Sum256(b)
		return s[:]
	case cryptoc.SHA384:
		s := sha512.Sum384(b)
		return s[:]
	case cryptoc.SHA512:
		s := sha512.Sum512(b)
		return s[:]
	}
	return nil
}

func ecdsaSignInto(privKey *ecdsa.PrivateKey, digest []byte, sig *C.uchar, siglen *C.size_t, sigsize C.size_t) C.int {
	// SignASN1: approved-mode signing with the canonical DER encoder.
	der, err := ecdsa.SignASN1(cryptorand.Reader, privKey, digest)
	if err != nil {
		return 0
	}
	if int(sigsize) < len(der) {
		// A size query (sigret NULL) reports the algorithm maximum (72 for
		// P-256, 104 for P-384), as ECDSA_size does: the DER length varies
		// per signature. With sigret set, a short buffer is an error.
		if sig == nil {
			*siglen = C.size_t(curveOf(privKey.Curve).maxSig)
			return 1
		}
		return 0
	}
	copy(unsafe.Slice((*byte)(unsafe.Pointer(sig)), len(der)), der)
	*siglen = C.size_t(len(der))
	recordOp("ecdsa")
	return 1
}

// decodeECDSASigDER is a structural pre-check before VerifyASN1, whose
// strict parser gives the verdict.

func decodeECDSASigDER(der []byte) (r, s *big.Int, err error) {
	if len(der) < 2 || der[0] != 0x30 {
		return nil, nil, fmt.Errorf("bad sig")
	}
	bodyLen := int(der[1])
	if bodyLen&0x80 != 0 {
		n := int(bodyLen & 0x7f)
		if n > 2 || len(der) < 2+n {
			return nil, nil, fmt.Errorf("bad len")
		}
		bodyLen = 0
		for i := 0; i < n; i++ {
			bodyLen = bodyLen<<8 | int(der[2+i])
		}
	}
	if 2+bodyLen > len(der) {
		return nil, nil, fmt.Errorf("bad body")
	}
	body := der[2 : 2+bodyLen]
	readInt := func(b []byte) (*big.Int, []byte, error) {
		if len(b) < 2 || b[0] != 0x02 {
			return nil, nil, fmt.Errorf("bad int")
		}
		l := int(b[1])
		if len(b) < 2+l {
			return nil, nil, fmt.Errorf("bad int len")
		}
		return new(big.Int).SetBytes(b[2 : 2+l]), b[2+l:], nil
	}
	r, body, err = readInt(body)
	if err != nil {
		return nil, nil, err
	}
	s, _, err = readInt(body)
	if err != nil {
		return nil, nil, err
	}
	return r, s, nil
}

// kdfMode reads an HKDF/TLS13-KDF mode as the default provider does: the
// names EXTRACT_AND_EXPAND, EXTRACT_ONLY, EXPAND_ONLY, or the integers 0-2.
func kdfMode(p *C.OSSL_PARAM) (int, bool) {
	var name string
	if getUtf8Param(p, &name) {
		switch name {
		case "EXTRACT_AND_EXPAND":
			return 0, true
		case "EXTRACT_ONLY":
			return 1, true
		case "EXPAND_ONLY":
			return 2, true
		}
		return 0, false
	}
	var v uint64
	if !getUintParam(p, &v) || v > 2 {
		return 0, false
	}
	return int(v), true
}

func getUtf8Param(p *C.OSSL_PARAM, out *string) bool {
	if p.data_type == C.OSSL_PARAM_UTF8_PTR {
		// data holds a char*; the string is what it points to.
		if p.data == nil {
			return false
		}
		sp := *(**C.char)(p.data)
		if sp == nil {
			return false
		}
		*out = C.GoString(sp)
		return true
	}
	if p.data_type != C.OSSL_PARAM_UTF8_STRING {
		return false
	}
	b := unsafe.Slice((*byte)(unsafe.Pointer(p.data)), int(p.data_size))
	for len(b) > 0 && b[len(b)-1] == 0 {
		b = b[:len(b)-1]
	}
	*out = string(b)
	return true
}

func getUintParam(p *C.OSSL_PARAM, out *uint64) bool {
	switch p.data_type {
	case C.OSSL_PARAM_UNSIGNED_INTEGER:
		switch p.data_size {
		case 1:
			*out = uint64(*(*uint8)(unsafe.Pointer(p.data)))
		case 2:
			*out = uint64(*(*uint16)(unsafe.Pointer(p.data)))
		case 4:
			*out = uint64(*(*uint32)(unsafe.Pointer(p.data)))
		case 8:
			*out = *(*uint64)(unsafe.Pointer(p.data))
		default:
			return false
		}
		return true
	case C.OSSL_PARAM_INTEGER:
		switch p.data_size {
		case 4:
			*out = uint64(*(*int32)(unsafe.Pointer(p.data)))
		case 8:
			*out = uint64(*(*int64)(unsafe.Pointer(p.data)))
		default:
			return false
		}
		return true
	}
	return false
}

// getOctetParam returns an input param's bytes (data_size of them, as
// OSSL_PARAM_get_octet_string reads). A buffer the caller says is non-empty
// but did not supply panics; every caller runs under opGuard, so the
// operation fails instead of using an empty value.
func getOctetParam(p *C.OSSL_PARAM) []byte {
	if p.data_size == 0 {
		return nil
	}
	if p.data == nil {
		panic("gofips: octet param with a size but no data")
	}
	return unsafe.Slice((*byte)(unsafe.Pointer(p.data)), int(p.data_size))
}

// ---- TLS13-KDF (OSSL_OP_KDF), the KDF TLS 1.3's key schedule fetches ----
//
// Semantics per OpenSSL 4.0.3 providers/implementations/kdfs/hkdf.c
// (kdf_tls1_3_derive):
//   EXTRACT_ONLY (1): prov_tls13_hkdf_generate_secret,
//     if prevsecret (salt) present: pre-extract = HKDF-Expand(prevsecret,
//       label(prefix||label), data=hash-of-empty), then
//       PRK = HKDF-Extract(preextract, insecret). Else PRK = Extract(zeros,
//       insecret). Output = PRK.
//   EXPAND_ONLY (2): prov_tls13_hkdf_expand,
//     HKDF-Expand(key=ikm, info=HKDF-label(outlen, prefix||label, data)).
//   EXTRACT_AND_EXPAND (0): refused at derive.
// The HKDF-label encoding (RFC 8446 §7.1): u16(len) u8(len(prefix||label))
// prefix label u8(len(data)) data.

type tls13kdfCtx struct {
	mu       sync.Mutex
	mode     int // EVP_KDF_HKDF_MODE_*
	hashFn   func() hash.Hash
	ikm      []byte // KEY param
	salt     []byte // SALT param (prev secret)
	saltSeen bool   // an explicitly present salt param, even empty;
	// lifecycle state, not param state: dup copies it (the dup of a
	// salted ctx derives the salted schedule), reset clears it (a reset
	// ctx with no salt param returns the salt-absent result).
	data   []byte // DATA param (expand context)
	prefix []byte
	label  []byte
}

//export gofips_tls13kdf_newctx
func gofips_tls13kdf_newctx(provctx *C.void) C.uint64_t {
	return handleGuard(func() C.uint64_t {
		dbg("tls13kdf_newctx")
		_ = provctx
		return C.uint64_t(regPut(&tls13kdfCtx{hashFn: sha256.New}))
	})
}

//export gofips_tls13kdf_freectx
func gofips_tls13kdf_freectx(kctx C.uint64_t) {
	if ctx := regGetTLS13KDF(uint64(kctx)); ctx != nil {
		withLock(&ctx.mu, func() { clear(ctx.ikm); ctx.ikm = nil })
	}
	regDel(uint64(kctx))
}

//export gofips_tls13kdf_reset
func gofips_tls13kdf_reset(kctx C.uint64_t) {
	ctx := regGetTLS13KDF(uint64(kctx))
	if ctx == nil {
		return
	}
	withLock(&ctx.mu, func() {
		ctx.ikm, ctx.salt, ctx.data, ctx.prefix, ctx.label = nil, nil, nil, nil, nil
		// Reset clears everything, as the default provider's: a reset ctx
		// derives as salt-absent, and a param-less derive is refused.
		ctx.saltSeen = false
		ctx.mode = 0
		ctx.hashFn = sha256.New
	})
}

// hkdfLabel encodes RFC 8446 §7.1 label: u16(len) u8(len(prefix||label))
// prefix||label u8(len(data)) data.
func hkdfLabel(outLen int, prefix, label, data []byte) []byte {
	pl := append(append([]byte(nil), prefix...), label...)
	out := make([]byte, 0, 2+1+len(pl)+1+len(data))
	out = append(out, byte(outLen>>8), byte(outLen))
	out = append(out, byte(len(pl)))
	out = append(out, pl...)
	out = append(out, byte(len(data)))
	out = append(out, data...)
	return out
}

//export gofips_tls13kdf_derive
func gofips_tls13kdf_derive(kctx C.uint64_t, key *C.uchar, keylen C.size_t, params *C.OSSL_PARAM) C.int {
	return opGuard(func() C.int { return tls13kdfDerive(kctx, key, keylen, params) })
}

func tls13kdfDerive(kctx C.uint64_t, key *C.uchar, keylen C.size_t, params *C.OSSL_PARAM) C.int {
	dbg("tls13kdf_derive keylen=%d", int(keylen))
	ctx := regGetTLS13KDF(uint64(kctx))
	if ctx == nil || key == nil || keylen == 0 {
		return 0
	}
	// EVP_KDF_derive forwards its params here directly (ctx-level
	// set_ctx_params is only for the persistent-context API).
	if err := tls13kdfApplyParams(ctx, params); err != 0 {
		return 0
	}
	ctx.mu.Lock()
	fn := ctx.hashFn
	mode := ctx.mode
	ikm := append([]byte(nil), ctx.ikm...)
	salt := append([]byte(nil), ctx.salt...)
	saltSeen := ctx.saltSeen
	data := append([]byte(nil), ctx.data...)
	prefix := append([]byte(nil), ctx.prefix...)
	label := append([]byte(nil), ctx.label...)
	ctx.mu.Unlock()

	out := unsafe.Slice((*byte)(unsafe.Pointer(key)), int(keylen))
	// Extract and expand go through crypto/hkdf (the module's HKDF); the
	// RFC 8446 §7.1 label framing is the adapter's, not a CAVP service row.
	switch mode {
	case 1: // EXTRACT_ONLY: generate_secret
		if saltSeen {
			// pre-extract: Expand(prevsecret, label(prefix||label),
			// data=hash-of-empty)
			empty := fn().Sum(nil)
			pre, err := hkdf.Expand(fn, salt, string(hkdfLabel(len(out), prefix, label, empty)), len(out))
			if err != nil {
				dbg("tls13kdf pre-Expand FAILED: %v", err)
				return 0
			}
			// An absent (or empty) key param means ikm = mdlen zero bytes
			// (RFC 8446 Extract(0,0) shape, e.g. the master secret:
			// Extract(derived-from-handshake, 0) where libssl omits the
			// key param), not the empty string.
			ikmUse := ikm
			if len(ikmUse) == 0 {
				ikmUse = make([]byte, fn().Size())
			}
			prk, err := hkdf.Extract(fn, ikmUse, pre)
			if err != nil {
				dbg("tls13kdf Extract FAILED: %v", err)
				return 0
			}
			copy(out, prk)
		} else {
			// PRK = HMAC(mdlen zero bytes, ikm). An absent (or empty) key
			// param means mdlen zero bytes, matching OpenSSL's default
			// TLS-1.3-KDF and RFC 8446's HKDF-Extract(0, 0), not the
			// empty string.
			zeros := make([]byte, fn().Size())
			ikmUse := ikm
			if len(ikmUse) == 0 {
				ikmUse = zeros
			}
			prk, err := hkdf.Extract(fn, ikmUse, zeros)
			if err != nil {
				dbg("tls13kdf Extract FAILED: %v", err)
				return 0
			}
			copy(out, prk)
		}
	case 2: // EXPAND_ONLY
		okm, err := hkdf.Expand(fn, ikm, string(hkdfLabel(len(out), prefix, label, data)), len(out))
		if err != nil {
			dbg("tls13kdf Expand FAILED: %v", err)
			return 0
		}
		copy(out, okm)
		if debugEnabled {
			dbg("tls13kdf EXPAND out=%x ikm=%x label=%x data=%x", out, ikm, label, data)
		}
	default:
		return 0 // EXTRACT_AND_EXPAND rejected (matches OpenSSL)
	}
	recordOp("kdf")
	return 1
}

// safeHead returns up to n bytes of p (nil-safe) for debug logging.
func safeHead(p unsafe.Pointer, n int) []byte {
	if p == nil || n <= 0 {
		return nil
	}
	if n > 48 {
		n = 48
	}
	return unsafe.Slice((*byte)(p), n)
}

// tls13kdfApplyParams applies derive/set params to the ctx. Returns 0 on
// success, nonzero on a rejected param (fail closed).
func tls13kdfApplyParams(ctx *tls13kdfCtx, params *C.OSSL_PARAM) int {
	if params == nil {
		return 0
	}
	for i := 0; i < paramCount(params); i++ {
		p := paramAt(params, i)
		if p.key == nil {
			break
		}
		if debugEnabled {
			dbg("tls13kdf param[%d] key=%q type=%d data_size=%d return_size=%d data[:8]=%x",
				i, C.GoString(p.key), int(p.data_type), int(p.data_size), int(p.return_size),
				safeHead(p.data, int(p.data_size)))
		}
		switch C.GoString(p.key) {
		case C.OSSL_KDF_PARAM_MODE:
			mode, good := kdfMode(p)
			if !good {
				return 1
			}
			withLock(&ctx.mu, func() {
				ctx.mode = mode
			})
		case C.OSSL_KDF_PARAM_DIGEST:
			var dn string
			if !getUtf8Param(p, &dn) {
				return 1
			}
			// SHA-256 or SHA-384, the TLS 1.3 suite hashes, under any of
			// their names (SHA3 has the same output sizes, other blocks).
			fn, approved := approvedDigest(dn)
			if !approved {
				return 1
			}
			if h := fn(); !(h.Size() == 32 && h.BlockSize() == 64) && !(h.Size() == 48 && h.BlockSize() == 128) {
				return 1
			}
			withLock(&ctx.mu, func() {
				ctx.hashFn = fn
			})
		case C.OSSL_KDF_PARAM_KEY:
			withLock(&ctx.mu, func() {
				ctx.ikm = append([]byte(nil), getOctetParam(p)...)
			})
		case C.OSSL_KDF_PARAM_SALT:
			// An explicitly present empty salt is distinct from an
			// absent one: absent means no pre-extract (plain
			// Extract(zeros, ikm)); present-empty means the pre-extract
			// runs with the raw salt bytes as the Expand key
			// (zero-padded by HKDF). Track presence separately.
			withLock(&ctx.mu, func() {
				ctx.salt = append([]byte(nil), getOctetParam(p)...)
				ctx.saltSeen = true
			})
		case C.OSSL_KDF_PARAM_DATA:
			withLock(&ctx.mu, func() {
				ctx.data = append([]byte(nil), getOctetParam(p)...)
			})
		case C.OSSL_KDF_PARAM_PREFIX:
			withLock(&ctx.mu, func() {
				ctx.prefix = append([]byte(nil), getOctetParam(p)...)
			})
		case C.OSSL_KDF_PARAM_LABEL:
			withLock(&ctx.mu, func() {
				ctx.label = append([]byte(nil), getOctetParam(p)...)
			})
		}
	}
	return 0
}

//export gofips_tls13kdf_set_ctx_params
func gofips_tls13kdf_set_ctx_params(kctx C.uint64_t, params *C.OSSL_PARAM) C.int {
	return opGuard(func() C.int { return tls13kdf_set_ctx_paramsOp(kctx, params) })
}

func tls13kdf_set_ctx_paramsOp(kctx C.uint64_t, params *C.OSSL_PARAM) C.int {
	ctx := regGetTLS13KDF(uint64(kctx))
	if ctx == nil {
		return 0
	}
	if tls13kdfApplyParams(ctx, params) == 0 {
		return 1
	}
	return 0
}

//export gofips_tls13kdf_settable_ctx_params
func gofips_tls13kdf_settable_ctx_params(kctx C.uint64_t, provctx *C.void) *C.OSSL_PARAM {
	_ = kctx
	_ = provctx
	return (*C.OSSL_PARAM)(unsafe.Pointer(&C.gofips_kdf_settable_ctx_params_tbl[0]))
}

//export gofips_tls13kdf_gettable_ctx_params
func gofips_tls13kdf_gettable_ctx_params(kctx C.uint64_t, provctx *C.void) *C.OSSL_PARAM {
	_ = kctx
	_ = provctx
	return nil
}

//export gofips_tls13kdf_get_ctx_params
func gofips_tls13kdf_get_ctx_params(kctx C.uint64_t, params *C.OSSL_PARAM) C.int {
	return opGuard(func() C.int { return tls13kdf_get_ctx_paramsOp(kctx, params) })
}

func tls13kdf_get_ctx_paramsOp(kctx C.uint64_t, params *C.OSSL_PARAM) C.int {
	_ = kctx
	_ = params
	return 1
}

//export gofips_tls13kdf_gettable_params
func gofips_tls13kdf_gettable_params(provctx *C.void) *C.OSSL_PARAM {
	_ = provctx
	return nil
}

//export gofips_tls13kdf_get_params
func gofips_tls13kdf_get_params(params *C.OSSL_PARAM) C.int {
	return opGuard(func() C.int { return tls13kdf_get_paramsOp(params) })
}

func tls13kdf_get_paramsOp(params *C.OSSL_PARAM) C.int {
	_ = params
	return 1
}

//export gofips_tls13kdf_dupctx
func gofips_tls13kdf_dupctx(src C.uint64_t) C.uint64_t {
	return handleGuard(func() C.uint64_t {
		s := regGetTLS13KDF(uint64(src))
		if s == nil {
			return 0
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		// saltSeen travels with the salt: a dup of a salted ctx pre-extracts.
		n := &tls13kdfCtx{mode: s.mode, hashFn: s.hashFn,
			ikm:      append([]byte(nil), s.ikm...),
			salt:     append([]byte(nil), s.salt...),
			saltSeen: s.saltSeen,
			data:     append([]byte(nil), s.data...),
			prefix:   append([]byte(nil), s.prefix...),
			label:    append([]byte(nil), s.label...)}
		return C.uint64_t(regPut(n))
	})
}
