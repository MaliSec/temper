package main

// hmac_pkey.go: HMAC as a key type and a signature, the form libssl uses
// for the TLS 1.3 PSK binder (session resumption): it wraps the binder key
// in an "HMAC" EVP_PKEY and signs with EVP_DigestSign. The MAC is the
// module's HMAC (crypto/hmac), under the same digest and 112-bit key rules
// as the HMAC MAC operation.

// #define OSSL_provider_init SUPPRESSED_OSSL_provider_init
// #include <openssl/core_dispatch.h>
// #undef OSSL_provider_init
// #include <openssl/core_names.h>
// #include <openssl/params.h>
// #include <stdlib.h>
//
// extern const OSSL_PARAM gofips_hmac_key_types[3];
// extern int gofips_call_octet_cb(OSSL_CALLBACK *cb, void *cbarg, const char *key, const unsigned char *data, size_t len);
import "C"

import (
	cryptoc "crypto"
	"crypto/hmac"
	"crypto/subtle"
	"hash"
	"sync"
	"unsafe"
)

// hmacSignMax bounds the data one HMAC signature buffers. EVP_DigestSignFinal
// duplicates the context before finishing, and a streaming HMAC cannot be
// cloned through the public Go API, so the signature keeps its input.
const hmacSignMax = 1 << 20

type hmacKey struct {
	mu  sync.Mutex
	key []byte
}

func regGetHmacKey(id uint64) *hmacKey {
	k, _ := regGet(id).(*hmacKey)
	return k
}

//export gofips_hmac_keymgmt_new
func gofips_hmac_keymgmt_new(provctx *C.void) C.uint64_t {
	return handleGuard(func() C.uint64_t {
		_ = provctx
		return C.uint64_t(regPut(&hmacKey{}))
	})
}

//export gofips_hmac_keymgmt_free
func gofips_hmac_keymgmt_free(keydata C.uint64_t) {
	if k := regGetHmacKey(uint64(keydata)); k != nil {
		withLock(&k.mu, func() { clear(k.key); k.key = nil })
	}
	regDel(uint64(keydata))
}

//export gofips_hmac_keymgmt_has
func gofips_hmac_keymgmt_has(keydata C.uint64_t, selection C.int) C.int {
	return opGuard(func() C.int {
		k := regGetHmacKey(uint64(keydata))
		if k == nil {
			return 0
		}
		k.mu.Lock()
		defer k.mu.Unlock()
		if selection&selPrivate != 0 && k.key == nil {
			return 0
		}
		return 1
	})
}

//export gofips_hmac_keymgmt_import
func gofips_hmac_keymgmt_import(keydata C.uint64_t, selection C.int, params *C.OSSL_PARAM) C.int {
	return opGuard(func() C.int {
		k := regGetHmacKey(uint64(keydata))
		if k == nil || params == nil || selection&selPrivate == 0 {
			return 0
		}
		var key []byte
		found := false
		for i := 0; i < paramCount(params); i++ {
			p := paramAt(params, i)
			if p.key == nil {
				break
			}
			if C.GoString(p.key) == C.OSSL_PKEY_PARAM_PRIV_KEY {
				key, found = getOctetParam(p), true
			}
		}
		if !found {
			return 0
		}
		withLock(&k.mu, func() { clear(k.key); k.key = append([]byte{}, key...) })
		return 1
	})
}

//export gofips_hmac_keymgmt_export
func gofips_hmac_keymgmt_export(keydata C.uint64_t, selection C.int, cb *C.OSSL_CALLBACK, cbarg *C.void) C.int {
	return opGuard(func() C.int {
		k := regGetHmacKey(uint64(keydata))
		if k == nil || cb == nil || selection&selPrivate == 0 {
			return 0
		}
		k.mu.Lock()
		key := append([]byte{}, k.key...)
		k.mu.Unlock()
		defer clear(key)
		if key == nil {
			return 0
		}
		var data *C.uchar
		if len(key) > 0 {
			data = (*C.uchar)(unsafe.Pointer(&key[0]))
		}
		cn := C.CString(C.OSSL_PKEY_PARAM_PRIV_KEY)
		defer C.free(unsafe.Pointer(cn))
		return C.gofips_call_octet_cb(cb, unsafe.Pointer(cbarg), cn, data, C.size_t(len(key)))
	})
}

//export gofips_hmac_keymgmt_key_types
func gofips_hmac_keymgmt_key_types(selection C.int) *C.OSSL_PARAM {
	_ = selection
	return &C.gofips_hmac_key_types[0]
}

//export gofips_hmac_keymgmt_match
func gofips_hmac_keymgmt_match(a, b C.uint64_t, selection C.int) C.int {
	return opGuard(func() C.int {
		_ = selection
		k1, k2 := regGetHmacKey(uint64(a)), regGetHmacKey(uint64(b))
		if k1 == nil || k2 == nil {
			return 0
		}
		k1.mu.Lock()
		x := append([]byte{}, k1.key...)
		k1.mu.Unlock()
		k2.mu.Lock()
		y := append([]byte{}, k2.key...)
		k2.mu.Unlock()
		defer clear(x)
		defer clear(y)
		if len(x) == 0 || len(y) == 0 {
			return 0 // a key without key material matches nothing
		}
		return C.int(subtle.ConstantTimeCompare(x, y))
	})
}

//export gofips_hmac_keymgmt_dup
func gofips_hmac_keymgmt_dup(keydata C.uint64_t, selection C.int) C.uint64_t {
	return handleGuard(func() C.uint64_t {
		_ = selection
		k := regGetHmacKey(uint64(keydata))
		if k == nil {
			return 0
		}
		k.mu.Lock()
		defer k.mu.Unlock()
		d := &hmacKey{}
		if k.key != nil {
			d.key = append([]byte{}, k.key...)
		}
		return C.uint64_t(regPut(d))
	})
}

var queryNameHMAC = C.CString("HMAC")

//export gofips_hmac_keymgmt_query_operation_name
func gofips_hmac_keymgmt_query_operation_name(operationID C.int) *C.char {
	if operationID == C.OSSL_OP_SIGNATURE {
		return queryNameHMAC
	}
	return nil
}

// ---- signature ----

type hmacSigCtx struct {
	mu     sync.Mutex
	key    []byte
	digest cryptoc.Hash
	buf    []byte
}

func regGetHmacSig(id uint64) *hmacSigCtx {
	s, _ := regGet(id).(*hmacSigCtx)
	return s
}

//export gofips_hmac_sig_newctx
func gofips_hmac_sig_newctx(provctx *C.void, propq *C.char) C.uint64_t {
	return handleGuard(func() C.uint64_t {
		_, _ = provctx, propq
		return C.uint64_t(regPut(&hmacSigCtx{}))
	})
}

//export gofips_hmac_sig_freectx
func gofips_hmac_sig_freectx(sctx C.uint64_t) {
	if s := regGetHmacSig(uint64(sctx)); s != nil {
		withLock(&s.mu, func() { clear(s.key); clear(s.buf); s.key, s.buf = nil, nil })
	}
	regDel(uint64(sctx))
}

//export gofips_hmac_sig_dupctx
func gofips_hmac_sig_dupctx(sctx C.uint64_t) C.uint64_t {
	return handleGuard(func() C.uint64_t {
		s := regGetHmacSig(uint64(sctx))
		if s == nil {
			return 0
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		return C.uint64_t(regPut(&hmacSigCtx{
			key:    append([]byte(nil), s.key...),
			digest: s.digest,
			buf:    append([]byte(nil), s.buf...),
		}))
	})
}

//export gofips_hmac_sig_digest_sign_init
func gofips_hmac_sig_digest_sign_init(sctx C.uint64_t, mdname *C.char, provkey C.uint64_t, params *C.OSSL_PARAM) C.int {
	return opGuard(func() C.int {
		_ = params
		s, k := regGetHmacSig(uint64(sctx)), regGetHmacKey(uint64(provkey))
		if s == nil || k == nil || mdname == nil {
			return 0
		}
		d := hmacHashFromName(C.GoString(mdname))
		if d == 0 || hmacHashNew(d) == nil {
			return 0
		}
		k.mu.Lock()
		key := append([]byte(nil), k.key...)
		k.mu.Unlock()
		if len(key) < 14 { // 112 bits, as the HMAC MAC operation
			clear(key)
			return 0
		}
		withLock(&s.mu, func() {
			clear(s.key)
			clear(s.buf)
			s.key, s.digest, s.buf = key, d, nil
		})
		return 1
	})
}

//export gofips_hmac_sig_digest_sign_update
func gofips_hmac_sig_digest_sign_update(sctx C.uint64_t, data *C.uchar, datalen C.size_t) C.int {
	return opGuard(func() C.int {
		s := regGetHmacSig(uint64(sctx))
		if s == nil || (data == nil && datalen > 0) {
			return 0
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.key == nil || uint64(len(s.buf))+uint64(datalen) > hmacSignMax {
			return 0
		}
		if datalen > 0 {
			s.buf = append(s.buf, unsafe.Slice((*byte)(unsafe.Pointer(data)), int(datalen))...)
		}
		return 1
	})
}

//export gofips_hmac_sig_digest_sign_final
func gofips_hmac_sig_digest_sign_final(sctx C.uint64_t, sig *C.uchar, siglen *C.size_t, sigsize C.size_t) C.int {
	return opGuard(func() C.int {
		s := regGetHmacSig(uint64(sctx))
		if s == nil || siglen == nil {
			return 0
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.key == nil {
			return 0
		}
		d := s.digest
		m := hmac.New(func() hash.Hash { return hmacHashNew(d) }, s.key)
		if sig == nil {
			*siglen = C.size_t(m.Size())
			return 1
		}
		if int(sigsize) < m.Size() {
			return 0
		}
		m.Write(s.buf)
		out := m.Sum(nil)
		copy(unsafe.Slice((*byte)(unsafe.Pointer(sig)), len(out)), out)
		*siglen = C.size_t(len(out))
		return 1
	})
}
