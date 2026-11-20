package main

// kdf_sha3.go: the SHA-3 and SHAKE digests and the PBKDF2 KDF. They use the
// public crypto/sha3 and crypto/pbkdf2 APIs, which in a GOFIPS140 build are
// the module's FIPS 202 and SP 800-132 services (SP 5247 Table 6).

// #define OSSL_provider_init SUPPRESSED_OSSL_provider_init
// #include <openssl/core_dispatch.h>
// #undef OSSL_provider_init
// #include <openssl/core_names.h>
// #include <openssl/params.h>
//
// extern const OSSL_PARAM gofips_shake_settable_ctx_params_tbl[2];
// extern const OSSL_PARAM gofips_pbkdf2_settable_ctx_params_tbl[7];
// extern const OSSL_PARAM gofips_pbkdf2_gettable_ctx_params_tbl[2];
import "C"

import (
	"crypto/pbkdf2"
	"crypto/sha256"
	"crypto/sha3"
	"crypto/sha512"
	"hash"
	"strings"
	"sync"
	"unsafe"
)

// approvedDigest maps an OpenSSL digest name to the module hash used by
// HMAC, HKDF and PBKDF2. SHA-2 and SHA-3 only: SP 5247 Table 8 lists any
// other hash as non-approved for these services.
func approvedDigest(name string) (func() hash.Hash, bool) {
	switch strings.ToUpper(name) {
	case "SHA2-256", "SHA-256", "SHA256", "2.16.840.1.101.3.4.2.1":
		return sha256.New, true
	case "SHA2-384", "SHA-384", "SHA384", "2.16.840.1.101.3.4.2.2":
		return sha512.New384, true
	case "SHA2-512", "SHA-512", "SHA512", "2.16.840.1.101.3.4.2.3":
		return sha512.New, true
	case "SHA3-224", "2.16.840.1.101.3.4.2.7":
		return func() hash.Hash { return sha3.New224() }, true
	case "SHA3-256", "2.16.840.1.101.3.4.2.8":
		return func() hash.Hash { return sha3.New256() }, true
	case "SHA3-384", "2.16.840.1.101.3.4.2.9":
		return func() hash.Hash { return sha3.New384() }, true
	case "SHA3-512", "2.16.840.1.101.3.4.2.10":
		return func() hash.Hash { return sha3.New512() }, true
	}
	return nil, false
}

func setIntParam(p *C.OSSL_PARAM, v int) bool {
	if p.data == nil {
		p.return_size = C.size_t(unsafe.Sizeof(C.int(0)))
		return true
	}
	switch p.data_size {
	case 4:
		*(*int32)(unsafe.Pointer(p.data)) = int32(v)
	case 8:
		*(*int64)(unsafe.Pointer(p.data)) = int64(v)
	default:
		return false
	}
	p.return_size = p.data_size
	return true
}

// ---- SHA-3 and SHAKE digests (OSSL_OP_DIGEST) ----
//
// One implementation for all six. variant is the digest's bit size for
// SHA3-224/256/384/512, and 128 or 256 (with xof set) for SHAKE. The C
// side passes it from a per-variant newctx and get_params (dispatch.c).

type sha3Ctx struct {
	mu      sync.Mutex
	variant int
	xof     bool
	h       hash.Hash   // SHA-3
	x       *sha3.SHAKE // SHAKE
	xoflen  int         // SHAKE output length; 0 until set (no default, as in OpenSSL 4)
}

func (c *sha3Ctx) reset() {
	switch {
	case c.xof && c.variant == 128:
		c.x = sha3.NewSHAKE128()
	case c.xof && c.variant == 256:
		c.x = sha3.NewSHAKE256()
	case c.variant == 224:
		c.h = sha3.New224()
	case c.variant == 256:
		c.h = sha3.New256()
	case c.variant == 384:
		c.h = sha3.New384()
	case c.variant == 512:
		c.h = sha3.New512()
	}
}

func sha3Sizes(variant int, xof bool) (size, block uint64) {
	if xof {
		if variant == 128 {
			return 0, 168
		}
		return 0, 136
	}
	return uint64(variant / 8), uint64(200 - 2*variant/8)
}

func regGetSha3(id uint64) *sha3Ctx {
	c, _ := regGet(id).(*sha3Ctx)
	return c
}

//export gofips_sha3_newctx
func gofips_sha3_newctx(variant C.int, xof C.int) C.uint64_t {
	return handleGuard(func() C.uint64_t {
		c := &sha3Ctx{variant: int(variant), xof: xof != 0}
		c.reset()
		if c.h == nil && c.x == nil {
			return 0
		}
		return C.uint64_t(regPut(c))
	})
}

//export gofips_sha3_init
func gofips_sha3_init(dctx C.uint64_t, params *C.OSSL_PARAM) C.int {
	return opGuard(func() C.int {
		c := regGetSha3(uint64(dctx))
		if c == nil {
			return 0
		}
		withLock(&c.mu, func() { c.reset(); c.xoflen = 0 })
		if params != nil && paramCount(params) > 0 {
			return sha3SetCtxParams(c, params)
		}
		return 1
	})
}

//export gofips_sha3_update
func gofips_sha3_update(dctx C.uint64_t, in *C.uchar, inl C.size_t) C.int {
	return opGuard(func() C.int {
		c := regGetSha3(uint64(dctx))
		if c == nil || (in == nil && inl > 0) {
			return 0
		}
		b := unsafe.Slice((*byte)(unsafe.Pointer(in)), int(inl))
		withLock(&c.mu, func() {
			if c.xof {
				_, _ = c.x.Write(b)
			} else {
				_, _ = c.h.Write(b)
			}
		})
		return 1
	})
}

//export gofips_sha3_final
func gofips_sha3_final(dctx C.uint64_t, out *C.uchar, outl *C.size_t, outsz C.size_t) C.int {
	return opGuard(func() C.int {
		c := regGetSha3(uint64(dctx))
		if c == nil || out == nil || outl == nil {
			return 0
		}
		var sum []byte
		withLock(&c.mu, func() {
			if c.xof {
				if c.xoflen <= 0 {
					return // no output length set: refuse, as OpenSSL 4 does
				}
				sum = make([]byte, c.xoflen)
				_, _ = c.x.Read(sum)
			} else {
				sum = c.h.Sum(nil)
			}
		})
		if len(sum) == 0 || int(outsz) < len(sum) {
			return 0
		}
		copy(unsafe.Slice((*byte)(unsafe.Pointer(out)), len(sum)), sum)
		*outl = C.size_t(len(sum))
		recordOp("digest")
		return 1
	})
}

//export gofips_sha3_dupctx
func gofips_sha3_dupctx(src C.uint64_t) C.uint64_t {
	return handleGuard(func() C.uint64_t {
		s := regGetSha3(uint64(src))
		if s == nil {
			return 0
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		n := &sha3Ctx{variant: s.variant, xof: s.xof, xoflen: s.xoflen}
		n.reset()
		var state []byte
		var err error
		if s.xof {
			if state, err = s.x.MarshalBinary(); err == nil {
				err = n.x.UnmarshalBinary(state)
			}
		} else {
			m, _ := s.h.(interface{ MarshalBinary() ([]byte, error) })
			u, _ := n.h.(interface{ UnmarshalBinary([]byte) error })
			if m == nil || u == nil {
				return 0
			}
			if state, err = m.MarshalBinary(); err == nil {
				err = u.UnmarshalBinary(state)
			}
		}
		if err != nil {
			return 0
		}
		return C.uint64_t(regPut(n))
	})
}

//export gofips_sha3_freectx
func gofips_sha3_freectx(dctx C.uint64_t) {
	if c := regGetSha3(uint64(dctx)); c != nil {
		withLock(&c.mu, func() { c.h, c.x = nil, nil })
	}
	regDel(uint64(dctx))
}

//export gofips_sha3_get_params
func gofips_sha3_get_params(variant C.int, xof C.int, params *C.OSSL_PARAM) C.int {
	return opGuard(func() C.int {
		if params == nil {
			return 0
		}
		size, block := sha3Sizes(int(variant), xof != 0)
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
				if !setUint(p, block) {
					ok = 0
				}
			case C.OSSL_DIGEST_PARAM_XOF:
				x := 0
				if xof != 0 {
					x = 1
				}
				if !setIntParam(p, x) {
					ok = 0
				}
			case C.OSSL_DIGEST_PARAM_ALGID_ABSENT:
				if !setIntParam(p, 1) {
					ok = 0
				}
			}
		}
		return C.int(ok)
	})
}

//export gofips_sha3_set_ctx_params
func gofips_sha3_set_ctx_params(dctx C.uint64_t, params *C.OSSL_PARAM) C.int {
	return opGuard(func() C.int {
		c := regGetSha3(uint64(dctx))
		if c == nil {
			return 0
		}
		return sha3SetCtxParams(c, params)
	})
}

// sha3SetCtxParams accepts the SHAKE output length (xoflen, or size, its
// alias) and nothing else.
func sha3SetCtxParams(c *sha3Ctx, params *C.OSSL_PARAM) C.int {
	if params == nil {
		return 1
	}
	for i := 0; i < paramCount(params); i++ {
		p := paramAt(params, i)
		if p.key == nil {
			break
		}
		switch C.GoString(p.key) {
		case C.OSSL_DIGEST_PARAM_XOFLEN, C.OSSL_DIGEST_PARAM_SIZE:
			var n uint64
			if !c.xof || !getUintParam(p, &n) || n == 0 || n > 1<<30 {
				return 0
			}
			withLock(&c.mu, func() { c.xoflen = int(n) })
		default:
			return 0
		}
	}
	return 1
}

//export gofips_shake_settable_ctx_params
func gofips_shake_settable_ctx_params(dctx C.uint64_t, provctx *C.void) *C.OSSL_PARAM {
	_, _ = dctx, provctx
	return (*C.OSSL_PARAM)(unsafe.Pointer(&C.gofips_shake_settable_ctx_params_tbl[0]))
}

// ---- PBKDF2 (OSSL_OP_KDF) ----
//
// Refused, rather than recorded as non-approved: a salt under 128 bits or
// a hash outside SHA-2/SHA-3 (SP 5247 Table 8), and a derived key under
// 112 bits (the module's service indicator, IG C.M). The iteration count
// and password length are not SP conditions and are not enforced. There is
// no default digest: OpenSSL's default provider defaults to SHA-1, which
// is not approved for PBKDF2.

type pbkdf2Ctx struct {
	mu     sync.Mutex
	pass   []byte
	salt   []byte
	iter   uint64
	hashFn func() hash.Hash
}

const pbkdf2DefaultIter = 2048 // PKCS5_DEFAULT_ITER, as in OpenSSL

func regGetPbkdf2(id uint64) *pbkdf2Ctx {
	c, _ := regGet(id).(*pbkdf2Ctx)
	return c
}

func (c *pbkdf2Ctx) wipe() {
	for i := range c.pass {
		c.pass[i] = 0
	}
	c.pass, c.salt, c.hashFn, c.iter = nil, nil, nil, pbkdf2DefaultIter
}

//export gofips_pbkdf2_newctx
func gofips_pbkdf2_newctx(provctx *C.void) C.uint64_t {
	return handleGuard(func() C.uint64_t {
		_ = provctx
		return C.uint64_t(regPut(&pbkdf2Ctx{iter: pbkdf2DefaultIter}))
	})
}

//export gofips_pbkdf2_freectx
func gofips_pbkdf2_freectx(kctx C.uint64_t) {
	if c := regGetPbkdf2(uint64(kctx)); c != nil {
		withLock(&c.mu, c.wipe)
	}
	regDel(uint64(kctx))
}

//export gofips_pbkdf2_reset
func gofips_pbkdf2_reset(kctx C.uint64_t) {
	if c := regGetPbkdf2(uint64(kctx)); c != nil {
		withLock(&c.mu, c.wipe)
	}
}

//export gofips_pbkdf2_dupctx
func gofips_pbkdf2_dupctx(src C.uint64_t) C.uint64_t {
	return handleGuard(func() C.uint64_t {
		s := regGetPbkdf2(uint64(src))
		if s == nil {
			return 0
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		return C.uint64_t(regPut(&pbkdf2Ctx{
			pass: append([]byte(nil), s.pass...), salt: append([]byte(nil), s.salt...),
			iter: s.iter, hashFn: s.hashFn,
		}))
	})
}

//export gofips_pbkdf2_set_ctx_params
func gofips_pbkdf2_set_ctx_params(kctx C.uint64_t, params *C.OSSL_PARAM) C.int {
	return opGuard(func() C.int {
		c := regGetPbkdf2(uint64(kctx))
		if c == nil {
			return 0
		}
		return pbkdf2SetParams(c, params)
	})
}

func pbkdf2SetParams(c *pbkdf2Ctx, params *C.OSSL_PARAM) C.int {
	if params == nil {
		return 1
	}
	for i := 0; i < paramCount(params); i++ {
		p := paramAt(params, i)
		if p.key == nil {
			break
		}
		switch C.GoString(p.key) {
		case C.OSSL_KDF_PARAM_PASSWORD:
			if p.data == nil && p.data_size > 0 {
				return 0
			}
			pw := getOctetParam(p)
			withLock(&c.mu, func() {
				for i := range c.pass {
					c.pass[i] = 0
				}
				c.pass = append([]byte(nil), pw...)
			})
		case C.OSSL_KDF_PARAM_SALT:
			if p.data == nil && p.data_size > 0 {
				return 0
			}
			s := getOctetParam(p)
			if len(s) < 128/8 {
				dbg("pbkdf2 REFUSED: salt %d bytes < 128 bits (SP 5247 Table 8)", len(s))
				return 0
			}
			withLock(&c.mu, func() { c.salt = append([]byte(nil), s...) })
		case C.OSSL_KDF_PARAM_ITER:
			var n uint64
			if !getUintParam(p, &n) || n == 0 || (p.data_type == C.OSSL_PARAM_INTEGER && int64(n) < 0) {
				return 0
			}
			withLock(&c.mu, func() { c.iter = n })
		case C.OSSL_KDF_PARAM_DIGEST:
			var dn string
			if !getUtf8Param(p, &dn) {
				return 0
			}
			fn, ok := approvedDigest(dn)
			if !ok {
				dbg("pbkdf2 REFUSED: digest %q is not approved for PBKDF2", dn)
				return 0
			}
			withLock(&c.mu, func() { c.hashFn = fn })
		case C.OSSL_KDF_PARAM_PROPERTIES, C.OSSL_KDF_PARAM_PKCS5:
			// Accepted and ignored: the digest always comes from this
			// provider, and the SP conditions are always enforced.
		default:
			return 0
		}
	}
	return 1
}

//export gofips_pbkdf2_derive
func gofips_pbkdf2_derive(kctx C.uint64_t, key *C.uchar, keylen C.size_t, params *C.OSSL_PARAM) C.int {
	return opGuard(func() C.int {
		c := regGetPbkdf2(uint64(kctx))
		if c == nil || key == nil {
			return 0
		}
		if pbkdf2SetParams(c, params) != 1 {
			return 0
		}
		if keylen < 112/8 {
			dbg("pbkdf2 REFUSED: key %d bytes < 112 bits (IG C.M)", int(keylen))
			return 0
		}
		var pass, salt []byte
		var iter uint64
		var fn func() hash.Hash
		withLock(&c.mu, func() { pass, salt, iter, fn = c.pass, c.salt, c.iter, c.hashFn })
		if fn == nil || salt == nil || iter == 0 || iter > 1<<31-1 {
			return 0
		}
		dk, err := pbkdf2.Key(fn, string(pass), salt, int(iter), int(keylen))
		if err != nil || len(dk) != int(keylen) {
			return 0
		}
		copy(unsafe.Slice((*byte)(unsafe.Pointer(key)), int(keylen)), dk)
		for i := range dk {
			dk[i] = 0
		}
		recordOp("kdf")
		return 1
	})
}

//export gofips_pbkdf2_settable_ctx_params
func gofips_pbkdf2_settable_ctx_params(kctx C.uint64_t, provctx *C.void) *C.OSSL_PARAM {
	_, _ = kctx, provctx
	return (*C.OSSL_PARAM)(unsafe.Pointer(&C.gofips_pbkdf2_settable_ctx_params_tbl[0]))
}

//export gofips_pbkdf2_gettable_ctx_params
func gofips_pbkdf2_gettable_ctx_params(kctx C.uint64_t, provctx *C.void) *C.OSSL_PARAM {
	_, _ = kctx, provctx
	return (*C.OSSL_PARAM)(unsafe.Pointer(&C.gofips_pbkdf2_gettable_ctx_params_tbl[0]))
}

//export gofips_pbkdf2_get_ctx_params
func gofips_pbkdf2_get_ctx_params(kctx C.uint64_t, params *C.OSSL_PARAM) C.int {
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
			if C.GoString(p.key) != C.OSSL_KDF_PARAM_SIZE || !setUint(p, ^uint64(0)) {
				return 0 // unknown keys fail, like the default provider
			}
		}
		return 1
	})
}
