package main

// rsa.go: RSA public keys and RSA signature verification (PKCS#1 v1.5 and
// PSS), for certificate chains and TLS 1.3 peers that use RSA. Verification
// only: the key manager imports public keys and refuses private ones, and
// the signature operation has no sign entry points. crypto/rsa in a
// GOFIPS140 build is the module's FIPS 186-5 RSA SigVer (SP 5247 Table 6).

// #define OSSL_provider_init SUPPRESSED_OSSL_provider_init
// #include <openssl/core_dispatch.h>
// #undef OSSL_provider_init
// #include <openssl/core_names.h>
// #include <openssl/params.h>
// #include <stdlib.h>
//
// extern const OSSL_PARAM gofips_rsa_key_types[3];
// extern const OSSL_PARAM gofips_rsa_keymgmt_params[7];
// extern const OSSL_PARAM gofips_rsa_sig_settable_tbl[8];
// extern const OSSL_PARAM gofips_rsa_sig_gettable_tbl[4];
// extern int gofips_build_rsa_export_params(OSSL_PARAM out[], const unsigned char *n, size_t nlen, const unsigned char *e, size_t elen);
// extern int gofips_call_param_cb(OSSL_CALLBACK *cb, void *cbarg, const OSSL_PARAM params[]);
import "C"

import (
	cryptoc "crypto"
	"crypto/rsa"
	"hash"
	"math"
	"math/big"
	"strconv"
	"sync"
	"unsafe"
)

const (
	selPrivate = 0x01 // OSSL_KEYMGMT_SELECT_PRIVATE_KEY
	selPublic  = 0x02 // OSSL_KEYMGMT_SELECT_PUBLIC_KEY

	padPKCS1 = 1 // RSA_PKCS1_PADDING
	padPSS   = 6 // RSA_PKCS1_PSS_PADDING

	// PSS salt lengths, as OpenSSL numbers them. FIPS 186-5 section 5.4
	// limits the salt to the hash length, so "max" is refused and "auto"
	// accepts only a salt of the digest length (Go cannot report the salt
	// length it detected).
	saltDigest  = -1 // RSA_PSS_SALTLEN_DIGEST
	saltAuto    = -2 // RSA_PSS_SALTLEN_AUTO and AUTO_DIGEST_MAX (-4)
	saltMax     = -3 // RSA_PSS_SALTLEN_MAX
	saltAutoMax = -4
)

type rsaKey struct {
	n   *big.Int
	e   int
	pss bool // an RSA-PSS key: PSS verification only
}

func regGetRsaKey(id uint64) *rsaKey {
	k, _ := regGet(id).(*rsaKey)
	return k
}

func (k *rsaKey) pub() *rsa.PublicKey { return &rsa.PublicKey{N: k.n, E: k.e} }

// bnFromParam reads an OSSL_PARAM integer: native-endian (little-endian on
// amd64 and arm64) for the integer types, big-endian for an octet string.
func bnFromParam(p *C.OSSL_PARAM) *big.Int {
	b := getOctetParam(p)
	if b == nil {
		return nil
	}
	if p.data_type == C.OSSL_PARAM_UNSIGNED_INTEGER {
		be := make([]byte, len(b))
		for i := range b {
			be[i] = b[len(b)-1-i]
		}
		return new(big.Int).SetBytes(be)
	}
	if p.data_type == C.OSSL_PARAM_OCTET_STRING {
		return new(big.Int).SetBytes(b)
	}
	return nil
}

func bnLE(v *big.Int) []byte {
	b := v.Bytes()
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return b
}

// setBNParam writes v for OSSL_PARAM_get_BN, with the default provider's
// buffer contract: a NULL buffer is a size query, a short one is an error,
// and data_size shrinks to the written length.
func setBNParam(p *C.OSSL_PARAM, v *big.Int) bool {
	le := bnLE(v)
	if p.data_type != C.OSSL_PARAM_UNSIGNED_INTEGER {
		return false
	}
	p.return_size = C.size_t(len(le))
	if p.data == nil {
		return true
	}
	if int(p.data_size) < len(le) {
		return false
	}
	copy(unsafe.Slice((*byte)(unsafe.Pointer(p.data)), int(p.data_size)), le)
	p.data_size = C.size_t(len(le))
	return true
}

// rsaSecurityBits follows OpenSSL's ossl_ifc_ffc_compute_security_bits:
// the canonical values for standard sizes, the SP 800-56B formula otherwise.
func rsaSecurityBits(n int) int {
	switch n {
	case 2048:
		return 112
	case 3072:
		return 128
	case 4096:
		return 152
	case 6144:
		return 176
	case 7680:
		return 192
	case 8192:
		return 200
	case 15360:
		return 256
	}
	if n < 8 {
		return 0
	}
	limit := 1200
	if n <= 7680 {
		limit = 192
	} else if n <= 15360 {
		limit = 256
	}
	x := float64(n) * math.Ln2
	y := (1.923*math.Cbrt(x*math.Log(x)*math.Log(x)) - 4.69) / math.Ln2
	bits := (int(y) + 4) &^ 7
	if bits > limit {
		bits = limit
	}
	return bits
}

// ---- key management ----

//export gofips_rsa_keymgmt_new
func gofips_rsa_keymgmt_new(provctx *C.void) C.uint64_t {
	return handleGuard(func() C.uint64_t {
		_ = provctx
		return C.uint64_t(regPut(&rsaKey{}))
	})
}

//export gofips_rsa_pss_keymgmt_new
func gofips_rsa_pss_keymgmt_new(provctx *C.void) C.uint64_t {
	return handleGuard(func() C.uint64_t {
		_ = provctx
		return C.uint64_t(regPut(&rsaKey{pss: true}))
	})
}

//export gofips_rsa_keymgmt_free
func gofips_rsa_keymgmt_free(keydata C.uint64_t) {
	regDel(uint64(keydata))
}

//export gofips_rsa_keymgmt_has
func gofips_rsa_keymgmt_has(keydata C.uint64_t, selection C.int) C.int {
	return opGuard(func() C.int {
		k := regGetRsaKey(uint64(keydata))
		if k == nil || selection&selPrivate != 0 || (selection&selPublic != 0 && k.n == nil) {
			return 0
		}
		return 1
	})
}

//export gofips_rsa_keymgmt_import
func gofips_rsa_keymgmt_import(keydata C.uint64_t, selection C.int, params *C.OSSL_PARAM) C.int {
	return opGuard(func() C.int { return rsaImport(keydata, selection, params) })
}

func rsaImport(keydata C.uint64_t, selection C.int, params *C.OSSL_PARAM) C.int {
	k := regGetRsaKey(uint64(keydata))
	if k == nil || params == nil || selection&selPublic == 0 {
		return 0
	}
	var n, e *big.Int
	for i := 0; i < paramCount(params); i++ {
		p := paramAt(params, i)
		if p.key == nil {
			break
		}
		switch C.GoString(p.key) {
		case C.OSSL_PKEY_PARAM_RSA_N:
			n = bnFromParam(p)
		case C.OSSL_PKEY_PARAM_RSA_E:
			e = bnFromParam(p)
		case C.OSSL_PKEY_PARAM_RSA_D:
			return 0 // private keys are not served
		default:
			// RSA-PSS restrictions and anything else we would not enforce.
			return 0
		}
	}
	if n == nil || e == nil || n.Sign() <= 0 || n.Bit(0) == 0 || !e.IsInt64() || e.Int64() < 3 || e.Int64() > math.MaxInt32 || e.Bit(0) == 0 {
		return 0
	}
	k.n, k.e = n, int(e.Int64())
	return 1
}

//export gofips_rsa_keymgmt_export
func gofips_rsa_keymgmt_export(keydata C.uint64_t, selection C.int, cb *C.OSSL_CALLBACK, cbarg *C.void) C.int {
	return opGuard(func() C.int {
		k := regGetRsaKey(uint64(keydata))
		if k == nil || k.n == nil || cb == nil || selection&selPrivate != 0 {
			return 0
		}
		n, e := bnLE(k.n), bnLE(big.NewInt(int64(k.e)))
		cn, ce := C.CBytes(n), C.CBytes(e)
		defer C.free(cn)
		defer C.free(ce)
		params := (*C.OSSL_PARAM)(C.malloc(C.size_t(unsafe.Sizeof(C.OSSL_PARAM{})) * 3))
		defer C.free(unsafe.Pointer(params))
		C.gofips_build_rsa_export_params(params, (*C.uchar)(cn), C.size_t(len(n)), (*C.uchar)(ce), C.size_t(len(e)))
		return C.gofips_call_param_cb(cb, unsafe.Pointer(cbarg), params)
	})
}

//export gofips_rsa_keymgmt_key_types
func gofips_rsa_keymgmt_key_types(selection C.int) *C.OSSL_PARAM {
	_ = selection
	return &C.gofips_rsa_key_types[0]
}

//export gofips_rsa_keymgmt_get_params
func gofips_rsa_keymgmt_get_params(keydata C.uint64_t, params *C.OSSL_PARAM) C.int {
	return opGuard(func() C.int {
		k := regGetRsaKey(uint64(keydata))
		if k == nil || k.n == nil || params == nil {
			return 0
		}
		bits := k.n.BitLen()
		for i := 0; i < paramCount(params); i++ {
			p := paramAt(params, i)
			if p.key == nil {
				break
			}
			ok := true
			switch C.GoString(p.key) {
			case C.OSSL_PKEY_PARAM_BITS:
				ok = setUint32(p, uint64(bits))
			case C.OSSL_PKEY_PARAM_SECURITY_BITS:
				ok = setUint32(p, uint64(rsaSecurityBits(bits)))
			case C.OSSL_PKEY_PARAM_MAX_SIZE:
				ok = setUint32(p, uint64((bits+7)/8))
			case C.OSSL_PKEY_PARAM_DEFAULT_DIGEST:
				ok = setUtf8Ptr(p, "SHA256")
			case C.OSSL_PKEY_PARAM_RSA_N:
				ok = setBNParam(p, k.n)
			case C.OSSL_PKEY_PARAM_RSA_E:
				ok = setBNParam(p, big.NewInt(int64(k.e)))
			}
			if !ok {
				return 0
			}
		}
		return 1
	})
}

//export gofips_rsa_keymgmt_gettable_params
func gofips_rsa_keymgmt_gettable_params(provctx *C.void) *C.OSSL_PARAM {
	_ = provctx
	return &C.gofips_rsa_keymgmt_params[0]
}

//export gofips_rsa_keymgmt_match
func gofips_rsa_keymgmt_match(a, b C.uint64_t, selection C.int) C.int {
	return opGuard(func() C.int {
		k1, k2 := regGetRsaKey(uint64(a)), regGetRsaKey(uint64(b))
		if k1 == nil || k2 == nil || k1.n == nil || k2.n == nil || selection&selPrivate != 0 {
			return 0
		}
		if k1.n.Cmp(k2.n) != 0 || k1.e != k2.e {
			return 0
		}
		return 1
	})
}

//export gofips_rsa_keymgmt_validate
func gofips_rsa_keymgmt_validate(keydata C.uint64_t, selection C.int, checkType C.int) C.int {
	return opGuard(func() C.int {
		_ = checkType
		k := regGetRsaKey(uint64(keydata))
		if k == nil || k.n == nil || selection&selPrivate != 0 {
			return 0
		}
		return 1
	})
}

//export gofips_rsa_keymgmt_dup
func gofips_rsa_keymgmt_dup(keydata C.uint64_t, selection C.int) C.uint64_t {
	return handleGuard(func() C.uint64_t {
		_ = selection
		k := regGetRsaKey(uint64(keydata))
		if k == nil {
			return 0
		}
		d := &rsaKey{e: k.e, pss: k.pss}
		if k.n != nil {
			d.n = new(big.Int).Set(k.n)
		}
		return C.uint64_t(regPut(d))
	})
}

var queryNameRSA = C.CString("RSA")

//export gofips_rsa_keymgmt_query_operation_name
func gofips_rsa_keymgmt_query_operation_name(operationID C.int) *C.char {
	if operationID == C.OSSL_OP_SIGNATURE {
		return queryNameRSA
	}
	return nil
}

// ---- signature verification ----

type rsaSigCtx struct {
	mu   sync.Mutex
	key  *rsaKey
	md   cryptoc.Hash
	mgf1 cryptoc.Hash // 0: same as md
	pad  int
	salt int
	h    hash.Hash // streaming digest_verify state
}

func regGetRsaSig(id uint64) *rsaSigCtx {
	s, _ := regGet(id).(*rsaSigCtx)
	return s
}

//export gofips_rsa_sig_newctx
func gofips_rsa_sig_newctx(provctx *C.void, propq *C.char) C.uint64_t {
	return handleGuard(func() C.uint64_t {
		_ = provctx
		_ = propq
		return C.uint64_t(regPut(&rsaSigCtx{pad: padPKCS1, salt: saltAuto}))
	})
}

//export gofips_rsa_sig_freectx
func gofips_rsa_sig_freectx(sctx C.uint64_t) {
	regDel(uint64(sctx))
}

//export gofips_rsa_sig_dupctx
func gofips_rsa_sig_dupctx(sctx C.uint64_t) C.uint64_t {
	return handleGuard(func() C.uint64_t {
		s := regGetRsaSig(uint64(sctx))
		if s == nil {
			return 0
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		d := &rsaSigCtx{key: s.key, md: s.md, mgf1: s.mgf1, pad: s.pad, salt: s.salt}
		if s.h != nil {
			if d.h = hashClone(s.h); d.h == nil {
				return 0
			}
		}
		return C.uint64_t(regPut(d))
	})
}

func rsaVerifyInit(sctx, provkey C.uint64_t, mdname *C.char, params *C.OSSL_PARAM) C.int {
	s, k := regGetRsaSig(uint64(sctx)), regGetRsaKey(uint64(provkey))
	if s == nil || k == nil || k.n == nil {
		return 0
	}
	var md cryptoc.Hash
	if mdname != nil {
		if md = sigMDFromName(C.GoString(mdname)); md == 0 {
			return 0
		}
	}
	withLock(&s.mu, func() {
		// Each init starts from the key type's defaults, as the default provider.
		s.key, s.h, s.md, s.mgf1, s.salt = k, nil, 0, 0, saltAuto
		s.pad = padPKCS1
		if k.pss {
			s.pad = padPSS
		}
		if md != 0 {
			s.md, s.h = md, sigHash(md)
		}
	})
	if params != nil {
		return rsaSetParams(s, params)
	}
	return 1
}

//export gofips_rsa_sig_verify_init
func gofips_rsa_sig_verify_init(sctx, provkey C.uint64_t, params *C.OSSL_PARAM) C.int {
	return opGuard(func() C.int { return rsaVerifyInit(sctx, provkey, nil, params) })
}

//export gofips_rsa_sig_digest_verify_init
func gofips_rsa_sig_digest_verify_init(sctx C.uint64_t, mdname *C.char, provkey C.uint64_t, params *C.OSSL_PARAM) C.int {
	return opGuard(func() C.int {
		if mdname == nil {
			mdname = queryNameSHA256
		}
		return rsaVerifyInit(sctx, provkey, mdname, params)
	})
}

var queryNameSHA256 = C.CString("SHA2-256")

// rsaVerifyDigest is the verdict for every RSA verify path.
func rsaVerifyDigest(s *rsaSigCtx, digest []byte, sig *C.uchar, siglen C.size_t) C.int {
	s.mu.Lock()
	k, md, mgf1, pad, salt := s.key, s.md, s.mgf1, s.pad, s.salt
	s.mu.Unlock()
	if k == nil || md == 0 || sig == nil || len(digest) != md.Size() {
		return 0
	}
	// The module marks these keys non-approved (rsa.checkPublicKey):
	// FIPS 186-5 sections 5.1 and 5.5(e).
	if bits := k.n.BitLen(); bits < 2048 || bits%2 == 1 || k.e <= 1<<16 {
		return 0
	}
	sigb := unsafe.Slice((*byte)(unsafe.Pointer(sig)), int(siglen))
	var err error
	switch pad {
	case padPKCS1:
		if k.pss {
			return 0
		}
		err = rsa.VerifyPKCS1v15(k.pub(), md, digest, sigb)
	case padPSS:
		if mgf1 != 0 && mgf1 != md {
			return 0 // Go's PSS uses the message hash for MGF1
		}
		opts := &rsa.PSSOptions{Hash: md, SaltLength: rsa.PSSSaltLengthEqualsHash}
		switch {
		case salt == saltDigest, salt == saltAuto:
		case salt > 0 && salt <= md.Size():
			opts.SaltLength = salt
		default:
			// "max", a salt longer than the hash, or 0 (Go reads 0 as auto).
			return 0
		}
		err = rsa.VerifyPSS(k.pub(), md, digest, sigb, opts)
	default:
		return 0
	}
	if err != nil {
		return 0
	}
	recordOp("rsa")
	return 1
}

//export gofips_rsa_sig_verify
func gofips_rsa_sig_verify(sctx C.uint64_t, sig *C.uchar, siglen C.size_t, tbs *C.uchar, tbslen C.size_t) C.int {
	return opGuard(func() C.int {
		s := regGetRsaSig(uint64(sctx))
		if s == nil || tbs == nil {
			return 0
		}
		return rsaVerifyDigest(s, append([]byte(nil), unsafe.Slice((*byte)(unsafe.Pointer(tbs)), int(tbslen))...), sig, siglen)
	})
}

//export gofips_rsa_sig_digest_verify
func gofips_rsa_sig_digest_verify(sctx C.uint64_t, sig *C.uchar, siglen C.size_t, tbs *C.uchar, tbslen C.size_t) C.int {
	return opGuard(func() C.int {
		s := regGetRsaSig(uint64(sctx))
		if s == nil || (tbs == nil && tbslen > 0) {
			return 0
		}
		s.mu.Lock()
		md := s.md
		s.mu.Unlock()
		h := sigHash(md)
		if h == nil {
			return 0
		}
		if tbslen > 0 {
			h.Write(unsafe.Slice((*byte)(unsafe.Pointer(tbs)), int(tbslen)))
		}
		return rsaVerifyDigest(s, h.Sum(nil), sig, siglen)
	})
}

//export gofips_rsa_sig_digest_verify_update
func gofips_rsa_sig_digest_verify_update(sctx C.uint64_t, data *C.uchar, datalen C.size_t) C.int {
	return opGuard(func() C.int {
		s := regGetRsaSig(uint64(sctx))
		if s == nil || (data == nil && datalen > 0) {
			return 0
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.h == nil {
			return 0
		}
		if datalen > 0 {
			s.h.Write(unsafe.Slice((*byte)(unsafe.Pointer(data)), int(datalen)))
		}
		return 1
	})
}

//export gofips_rsa_sig_digest_verify_final
func gofips_rsa_sig_digest_verify_final(sctx C.uint64_t, sig *C.uchar, siglen C.size_t) C.int {
	return opGuard(func() C.int {
		s := regGetRsaSig(uint64(sctx))
		if s == nil {
			return 0
		}
		s.mu.Lock()
		h := s.h
		s.mu.Unlock()
		if h == nil {
			return 0
		}
		return rsaVerifyDigest(s, h.Sum(nil), sig, siglen)
	})
}

func rsaSetParams(s *rsaSigCtx, params *C.OSSL_PARAM) C.int {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := 0; i < paramCount(params); i++ {
		p := paramAt(params, i)
		if p.key == nil {
			break
		}
		var str string
		var num uint64
		isStr := getUtf8Param(p, &str)
		switch C.GoString(p.key) {
		case C.OSSL_SIGNATURE_PARAM_PAD_MODE:
			switch {
			case isStr && str == "pkcs1":
				s.pad = padPKCS1
			case isStr && str == "pss":
				s.pad = padPSS
			case !isStr && getUintParam(p, &num) && (num == padPKCS1 || num == padPSS):
				s.pad = int(num)
			default:
				return 0
			}
		case C.OSSL_SIGNATURE_PARAM_DIGEST:
			md := sigMDFromName(str)
			if !isStr || md == 0 || (s.h != nil && md != s.md) {
				return 0
			}
			s.md = md
		case C.OSSL_SIGNATURE_PARAM_MGF1_DIGEST:
			md := sigMDFromName(str)
			if !isStr || md == 0 {
				return 0
			}
			s.mgf1 = md
		case C.OSSL_SIGNATURE_PARAM_PSS_SALTLEN:
			v := 0
			switch {
			case isStr && str == "digest":
				v = saltDigest
			case isStr && (str == "auto" || str == "auto-digestmax"):
				v = saltAuto
			case isStr && str == "max":
				v = saltMax
			case isStr:
				n, err := strconv.Atoi(str)
				if err != nil {
					return 0
				}
				v = n
			case getUintParam(p, &num):
				v = int(int32(num))
			default:
				return 0
			}
			if v == saltAutoMax {
				v = saltAuto
			}
			if v < saltMax {
				return 0
			}
			s.salt = v
		case C.OSSL_SIGNATURE_PARAM_PROPERTIES, C.OSSL_SIGNATURE_PARAM_MGF1_PROPERTIES, "tls-version":
		// newer libssl passes tls-version with the digest at init.
		default:
			return 0
		}
	}
	return 1
}

//export gofips_rsa_sig_set_ctx_params
func gofips_rsa_sig_set_ctx_params(sctx C.uint64_t, params *C.OSSL_PARAM) C.int {
	return opGuard(func() C.int {
		s := regGetRsaSig(uint64(sctx))
		if s == nil {
			return 0
		}
		if params == nil {
			return 1
		}
		return rsaSetParams(s, params)
	})
}

//export gofips_rsa_sig_get_ctx_params
func gofips_rsa_sig_get_ctx_params(sctx C.uint64_t, params *C.OSSL_PARAM) C.int {
	return opGuard(func() C.int {
		s := regGetRsaSig(uint64(sctx))
		if s == nil || params == nil {
			return 0
		}
		s.mu.Lock()
		pad, md, salt := s.pad, s.md, s.salt
		s.mu.Unlock()
		for i := 0; i < paramCount(params); i++ {
			p := paramAt(params, i)
			if p.key == nil {
				break
			}
			ok := true
			switch C.GoString(p.key) {
			case C.OSSL_SIGNATURE_PARAM_PAD_MODE:
				if p.data_type == C.OSSL_PARAM_UTF8_STRING {
					ok = setUtf8Ptr(p, map[int]string{padPKCS1: "pkcs1", padPSS: "pss"}[pad])
				} else {
					ok = setIntParam(p, pad)
				}
			case C.OSSL_SIGNATURE_PARAM_DIGEST:
				if md == 0 {
					return 0
				}
				ok = setUtf8Ptr(p, map[cryptoc.Hash]string{cryptoc.SHA256: "SHA2-256", cryptoc.SHA384: "SHA2-384", cryptoc.SHA512: "SHA2-512"}[md])
			case C.OSSL_SIGNATURE_PARAM_PSS_SALTLEN:
				ok = setIntParam(p, salt)
			}
			if !ok {
				return 0
			}
		}
		return 1
	})
}

//export gofips_rsa_sig_settable_ctx_params
func gofips_rsa_sig_settable_ctx_params(sctx C.uint64_t, provctx *C.void) *C.OSSL_PARAM {
	_ = sctx
	_ = provctx
	return &C.gofips_rsa_sig_settable_tbl[0]
}

//export gofips_rsa_sig_gettable_ctx_params
func gofips_rsa_sig_gettable_ctx_params(sctx C.uint64_t, provctx *C.void) *C.OSSL_PARAM {
	_ = sctx
	_ = provctx
	return &C.gofips_rsa_sig_gettable_tbl[0]
}
