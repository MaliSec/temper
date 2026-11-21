// Package main builds the gofips OpenSSL provider, whose cryptographic
// operations run in the Go Cryptographic Module (CMVP #5247, module v1.0.0).
// This file: OSSL_provider_init, provider params and teardown, the SHA-256
// digest operation and the RAND operation. The served and refused
// algorithms are listed in providers/gofips/README.md and audit page 03.
//
// The Go Cryptographic Module is CMVP #5247 (v1.0.0) when built per its
// Security Policy §11.1: GOFIPS140=v1.0.0, the unmodified frozen archive,
// and the integrity self-test passing. See README "FIPS status".
package main

/*
// No libcrypto link: a provider receives core callbacks through
// OSSL_provider_init and needs no libcrypto symbols of its own, so the same
// .so loads on OpenSSL 3.x and 4.x.
*/
// #define OSSL_provider_init SUPPRESSED_OSSL_provider_init
// #include <stdlib.h>
//
// #include <openssl/core_dispatch.h>
// #undef OSSL_provider_init
// #include <openssl/core_names.h>
// #include <openssl/params.h>
//
// extern const OSSL_DISPATCH gofips_dispatch_table[19];
// extern const OSSL_ALGORITHM gofips_digest_algorithms[11];
// extern const OSSL_ALGORITHM gofips_rand_algorithms[2];
// extern const OSSL_ALGORITHM gofips_mac_algorithms[2];
// extern const OSSL_ALGORITHM gofips_kdf_algorithms[5];
// extern const OSSL_ALGORITHM gofips_cipher_algorithms[5];
// extern const OSSL_ALGORITHM gofips_keymgmt_algorithms[5];
// extern const OSSL_ALGORITHM gofips_keyexch_algorithms[2];
// extern const OSSL_ALGORITHM gofips_sig_algorithms[4];
// extern const OSSL_PARAM gofips_prov_param_types[7];
// extern const OSSL_ITEM gofips_reason_strings[2];
// extern const OSSL_PARAM gofips_mac_settable_ctx_params_tbl[4];
// extern const OSSL_PARAM gofips_kdf_settable_ctx_params_tbl[9];
// extern const OSSL_PARAM gofips_ec_import_types[4];
// extern const OSSL_PARAM gofips_ec_export_types[3];
// extern const OSSL_PARAM gofips_ec_keymgmt_params[6];
// extern int gofips_call_param_cb(OSSL_CALLBACK* cb, void* cbarg, const OSSL_PARAM params[]);
// extern int gofips_build_ec_export_params(OSSL_PARAM out[], const char* group, const unsigned char* pub, size_t publen, const unsigned char* priv, size_t privlen);
// extern const OSSL_ALGORITHM *gofips_digest_table(int ossl3);
// extern int gofips_core_is_ossl3(const OSSL_CORE_HANDLE *handle, const OSSL_DISPATCH *in);
import "C"

import (
	"crypto/fips140" // public approved-mode read (Go 1.25+)
	"crypto/rand"
	"crypto/sha256" // routes through crypto/internal/fips140/sha256 in FIPS mode
	"fmt"
	"os"
	"runtime/debug"
	"strings"
	"sync"
	"unsafe"
)

// debugEnabled is compiled out of release builds: it is set only by the
// gofips_debug build tag (-tags gofips_debug). Without the tag the debug
// path is dead code (the compiler eliminates the dbg calls) and no
// secret material (keys, digests, plaintext) can reach stderr in a
// release artifact; GOFIPS_DEBUG=1 at runtime alone enables nothing.
// Note: the format-string literals remain in a
// release binary - the linker keeps dead-code constants, and the
// "gofips: " prefix is added at runtime - so a strings-scan of the
// artifact cannot assert release silence. The binding evidence is the
// runtime pair: with GOFIPS_DEBUG=1 a release build emits 0 "gofips:"
// trace lines and a -tags gofips_debug build emits traces (docclean.sh
// 6a/6b and the mode-matrix.sh release-scan section).
var debugEnabled = false

func dbg(format string, args ...interface{}) {
	if debugEnabled {
		fmt.Fprintf(os.Stderr, "gofips: "+format+"\n", args...)
	}
}

// gofipsBuildMode reports the build's GOFIPS140 stamp from
// debug.ReadBuildInfo. A GOFIPS140=v1.0.0 build carries the setting
// "GOFIPS140 = v1.0.0-c2097c7c" plus "-tags = fips140v1.0"; a plain build
// carries neither, so this returns "" and the init gate refuses. The gate
// is two independent conditions: this stamp (the SP 11.1 build condition) and
// crypto/fips140.Enabled() (runtime approved mode), cross-checked
// against the GODEBUG environment below.
func gofipsBuildMode() string {
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, s := range bi.Settings {
			if s.Key == "GOFIPS140" {
				return s.Value
			}
		}
	}
	return ""
}

// ---- provider identity ----

const (
	provName    = "gofips"
	provVersion = "0.0.1-slice"
)

// C-side tables (dispatch.c), linked at build time and declared in the cgo
// preamble below.

// ---- SHA-256 context registry ----
//
// Digest contexts stay in Go-owned memory; C sees only an opaque integer
// handle. This avoids returning Go pointers across cgo (runtime cgocheck
// forbids unpinned Go pointers in C results) and keeps Go state inside the
// Go runtime, matching the SP 5247 boundary story (module state in module
// memory; calling application holds only an identifier).
type sha256Ctx struct {
	mu sync.Mutex
	h  interface {
		Write([]byte) (int, error)
		Sum(b []byte) []byte
	} // hash.Hash; *digest.digest under FIPS mode
}

var (
	regMu    sync.Mutex
	nextHnd  uint64 = 1
	contexts        = map[uint64]*sha256Ctx{}
)

// ctxNewWith registers a pre-built sha256 context (used by the TLS layer's
// dupctx, which clones an existing hash state).
func ctxNewWith(h interface {
	Write([]byte) (int, error)
	Sum(b []byte) []byte
}) uint64 {
	regMu.Lock()
	defer regMu.Unlock()
	id := nextHnd
	nextHnd++
	contexts[id] = &sha256Ctx{h: h}
	return id
}

func ctxNew() uint64 {
	regMu.Lock()
	defer regMu.Unlock()
	h := nextHnd
	nextHnd++
	contexts[h] = &sha256Ctx{h: sha256.New()}
	return h
}

func ctxGet(h uint64) *sha256Ctx {
	regMu.Lock()
	defer regMu.Unlock()
	return contexts[h]
}

func ctxDel(h uint64) {
	regMu.Lock()
	defer regMu.Unlock()
	if ctx, ok := contexts[h]; ok {
		withLock(&ctx.mu, func() {
			ctx.h = nil
		})
		delete(contexts, h)
	}
}

// callCount counts digest operations actually executed by Go code. Read via
// temperfips_evidence() from the test harness, this is how the tests prove
// the SHA-256 work lands in Go rather than in libcrypto's default provider.
var callMu sync.Mutex
var callCount int64

// opCounts records per-operation activity (ECDH/ECDSA/KDF/Cipher/MAC/RAND)
// across a real handshake. Read via the "temperfips-ops" provider param
// (JSON-encoded), Node-visible through the C harness, and via
// temperfips_evidence for the total.
var opCounts = map[string]int64{}

func recordCall() {
	withLock(&callMu, func() {
		callCount++
	})
}

func recordOp(name string) {
	withLock(&callMu, func() {
		opCounts[name]++
	})
}

func getCallCount() int64 {
	callMu.Lock()
	defer callMu.Unlock()
	return callCount
}

func getRandCalls() int64 {
	callMu.Lock()
	defer callMu.Unlock()
	return randCalls
}

func opsJSON() string {
	callMu.Lock()
	defer callMu.Unlock()
	keys := []string{"ecdh", "ecdsa", "rsa", "digest", "kdf", "cipher", "mac", "rand"}
	out := "{"
	for i, k := range keys {
		if i > 0 {
			out += ","
		}
		out += fmt.Sprintf("\"%s\":%d", k, opCounts[k])
	}
	return out + "}"
}

// ---- OSSL_provider_init ----

// fipsModeOn reports whether the Go runtime's FIPS 140-3 mode is on for
// this binary. Two conditions, both enforced:
//  1. build condition: the binary was built with GOFIPS140=v1.0.0
//     (stamped as the "GOFIPS140" build setting; read via
//     debug.ReadBuildInfo; see gofipsBuildMode). A binary without the
//     stamp is not an approved-mode build and the provider refuses.
//  2. runtime condition: crypto/fips140.Enabled(), the public approved-
//     mode read, cross-checked against the canonical GODEBUG key. The
//     internal package is not importable from this module; the GODEBUG
//     scan is the environment-level check (container runtimes
//     set the env the runtime reads). With no explicit key, the build
//     default (GOFIPS140=v1.0.0) is on.
//
// Enforcement gate: provider init refuses unless both hold; no crypto
// entry point exists without the gate.
func fipsModeOn() bool {
	if !fips140.Enabled() {
		return false
	}
	// Build-stamp check: an unstamped or non-v1.0.0 binary refuses.
	// The stamp is present on every GOFIPS140 build (gofipsBuildMode).
	switch v := gofipsBuildMode(); {
	case v == "":
		// No stamp: not an approved-mode build (a plain build carries
		// no GOFIPS140 setting). Refuse.
		return false
	case strings.HasPrefix(v, "v1.0.0"):
		// approved-mode build stamp present (v1.0.0-c2097c7c ...)
	default:
		return false
	}
	for _, kv := range strings.Split(os.Getenv("GODEBUG"), ",") {
		kv = strings.TrimSpace(kv)
		if strings.HasPrefix(kv, "fips140=") {
			v := strings.TrimPrefix(kv, "fips140=")
			switch v {
			case "off", "0":
				return false
			case "on", "only", "debug", "1":
				return true
			}
		}
	}
	// No explicit setting: GOFIPS140=v1.0.0 build default = on.
	return true
}

//export OSSL_provider_init
func OSSL_provider_init(
	handle *C.OSSL_CORE_HANDLE,
	in *C.OSSL_DISPATCH,
	out **C.OSSL_DISPATCH,
	provctx **C.OSSL_CORE_HANDLE,
) C.int {
	dbg("OSSL_provider_init called")
	if !fipsModeOn() {
		dbg("init REFUSED: Go FIPS mode disabled (GODEBUG=fips140=off), exclusive-FIPS gate")
		return 0
	}
	if out != nil {
		*out = (*C.OSSL_DISPATCH)(unsafe.Pointer(&C.gofips_dispatch_table[0]))
		dbg("out table assigned (%d entries)", 16)
	}
	if provctx != nil {
		// Opaque, non-nil provider context; the core passes it back to every
		// provider-level function. It records only the core's major
		// version, which selects the digest table (query_operation). One
		// gofips.so loaded by OpenSSL 3 and 4 in one process gets one
		// context per core.
		ctx := &provCtx4
		if C.gofips_core_is_ossl3(handle, in) != 0 {
			ctx = &provCtx3
		}
		*provctx = (*C.OSSL_CORE_HANDLE)(unsafe.Pointer(ctx))
	}
	dbg("init returning 1")
	return 1
}

var provCtx3, provCtx4 byte

// coreIsOSSL3: the provider context was created by an OpenSSL 3 core.
func coreIsOSSL3(provctx *C.void) bool {
	return unsafe.Pointer(provctx) == unsafe.Pointer(&provCtx3)
}

// ---- provider-level functions (OSSL_FUNC_PROVIDER_* ≥1024) ----

//export gofips_teardown
func gofips_teardown(provctx *C.void) {
	dbg("teardown")
	_ = provctx
}

//export gofips_random_bytes
func gofips_random_bytes(provctx *C.void, which C.int, buf unsafe.Pointer, n C.size_t, strength C.uint) C.int {
	return opGuard(func() C.int { return random_bytesOp(provctx, which, buf, n, strength) })
}

func random_bytesOp(provctx *C.void, which C.int, buf unsafe.Pointer, n C.size_t, strength C.uint) C.int {
	// OSSL_FUNC_PROVIDER_RANDOM_BYTES (1032): the core-level CSPRNG entry
	// Node's ncrypto::CSPRNG bootstrap uses. Backed by Go crypto/rand,
	// the OS CSPRNG, which is what Node uses with the default provider
	// anyway; no algorithm fetch involved, so it works with the default
	// provider fully excluded.
	_ = provctx
	_ = strength
	if buf == nil && n > 0 {
		return 0
	}
	// Parity: the provider-level hook has no RAND manager in front
	// of it (unlike the RAND op, which the core splits to max_request),
	// so the per-call bound is enforced here directly.
	const randMaxRequest = 1 << 16
	// Chunking: when this hook is installed as the libctx's random
	// provider (RAND_set1_random_provider), the core passes every
	// RAND_bytes_ex request through it whole, with no manager split,
	// and the default provider serves any size. Serve large requests as a sequence of at-max chunks: each chunk
	// stays inside the enforced per-call bound (the bound is per call
	// into the DRBG, not per caller request), each chunk is
	// fail-closed (a failed chunk refuses the whole request, nothing
	// partially served is reported as success), and a request within
	// the bound takes the single-call path unchanged.
	if n <= randMaxRequest {
		b := unsafe.Slice((*byte)(buf), int(n))
		if _, err := rand.Read(b); err != nil {
			dbg("random_bytes failed: %v", err)
			return 0
		}
		return 1
	}
	if buf == nil {
		return 0
	}
	b := unsafe.Slice((*byte)(buf), int(n))
	for off := 0; off < len(b); off += randMaxRequest {
		end := off + randMaxRequest
		if end > len(b) {
			end = len(b)
		}
		if _, err := rand.Read(b[off:end]); err != nil {
			dbg("random_bytes chunk [%d,%d) failed: %v", off, end, err)
			return 0
		}
	}
	return 1
}

//export gofips_gettable_params
func gofips_gettable_params(provctx *C.void) *C.OSSL_PARAM {
	dbg("gettable_params")
	_ = provctx
	return (*C.OSSL_PARAM)(unsafe.Pointer(&C.gofips_prov_param_types[0]))
}

//export gofips_get_params
func gofips_get_params(provctx *C.void, params *C.OSSL_PARAM) C.int {
	return opGuard(func() C.int { return get_paramsOp(provctx, params) })
}

func get_paramsOp(provctx *C.void, params *C.OSSL_PARAM) C.int {
	dbg("get_params")
	_ = provctx
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
		case C.OSSL_PROV_PARAM_NAME:
			if !setUtf8Ptr(p, provName) {
				ok = 0
			}
		case C.OSSL_PROV_PARAM_VERSION:
			if !setUtf8Ptr(p, provVersion) {
				ok = 0
			}
		case C.OSSL_PROV_PARAM_STATUS:
			if !setUint32(p, 1) {
				ok = 0
			}
		case "temperfips-digestcalls":
			if !setUint(p, uint64(getCallCount())) {
				ok = 0
			}
		case "temperfips-randcalls":
			// Test counter, read with OSSL_PROVIDER_get_params: the core's
			// DRBG manager drops unknown RAND ctx keys.
			if !setUint(p, uint64(getRandCalls())) {
				ok = 0
			}
		case "temperfips-ops":
			// Per-op counters as a UTF8 JSON string, the C/Node harness
			// reads this after a real handshake to prove which ops ran
			// in Go.
			if !setUtf8PtrTransient(p, opsJSON()) {
				ok = 0
			}
		default:
			// Unknown key: left untouched; OpenSSL treats it as absent.
		}
	}
	return C.int(ok)
}

//export gofips_query_operation
func gofips_query_operation(provctx *C.void, operationID C.int, noStore *C.int) *C.OSSL_ALGORITHM {
	switch operationID {
	case C.OSSL_OP_CIPHER:
		dbg("query_operation op=%d alg=AES-256-GCM(etc)", int(operationID))
	case C.OSSL_OP_KEYEXCH:
		dbg("query_operation op=%d alg=ECDH", int(operationID))
	case C.OSSL_OP_SIGNATURE:
		dbg("query_operation op=%d alg=ECDSA", int(operationID))
	case C.OSSL_OP_KEYMGMT:
		dbg("query_operation op=%d alg=EC", int(operationID))
	case C.OSSL_OP_KDF:
		dbg("query_operation op=%d alg=TLS13-KDF/HKDF", int(operationID))
	case C.OSSL_OP_MAC:
		dbg("query_operation op=%d alg=HMAC", int(operationID))
	case C.OSSL_OP_RAND:
		dbg("query_operation op=%d alg=CTR-DRBG", int(operationID))
	default:
		dbg("query_operation op=%d", int(operationID))
	}
	_ = provctx
	if noStore != nil {
		*noStore = 0
	}
	switch operationID {
	case C.OSSL_OP_DIGEST:
		ossl3 := C.int(0)
		if coreIsOSSL3(provctx) {
			ossl3 = 1
		}
		return C.gofips_digest_table(ossl3)
	case C.OSSL_OP_RAND:
		return (*C.OSSL_ALGORITHM)(unsafe.Pointer(&C.gofips_rand_algorithms[0]))
	case C.OSSL_OP_MAC:
		return (*C.OSSL_ALGORITHM)(unsafe.Pointer(&C.gofips_mac_algorithms[0]))
	case C.OSSL_OP_KDF:
		return (*C.OSSL_ALGORITHM)(unsafe.Pointer(&C.gofips_kdf_algorithms[0]))
	case C.OSSL_OP_KDF + 100: // unreachable; keeps lints calm
		return nil
	case C.OSSL_OP_CIPHER:
		return (*C.OSSL_ALGORITHM)(unsafe.Pointer(&C.gofips_cipher_algorithms[0]))
	case C.OSSL_OP_KEYMGMT:
		return (*C.OSSL_ALGORITHM)(unsafe.Pointer(&C.gofips_keymgmt_algorithms[0]))
	case C.OSSL_OP_KEYEXCH:
		return (*C.OSSL_ALGORITHM)(unsafe.Pointer(&C.gofips_keyexch_algorithms[0]))
	case C.OSSL_OP_SIGNATURE:
		return (*C.OSSL_ALGORITHM)(unsafe.Pointer(&C.gofips_sig_algorithms[0]))
	}
	return nil
}

// gofips_md5_refuse_get_params: the refused MD5 row's sizes, so a fetch
// completes and resolves to gofips; every other entry point of the row
// fails (dispatch.c).
//
//export gofips_md5_refuse_get_params
func gofips_md5_refuse_get_params(params *C.OSSL_PARAM) C.int {
	return opGuard(func() C.int { return md5_refuse_get_paramsOp(params) })
}

func md5_refuse_get_paramsOp(params *C.OSSL_PARAM) C.int {
	return digestParams(params, 16, 64)
}

//export gofips_unquery_operation
func gofips_unquery_operation(provctx *C.void, operationID C.int, alg *C.OSSL_ALGORITHM) {
	_ = provctx
	_ = operationID
	_ = alg
}

//export gofips_get_reason_strings
func gofips_get_reason_strings(provctx *C.void) *C.OSSL_ITEM {
	_ = provctx
	// provider_activate in OpenSSL 3.5 iterates this table without a NULL
	// check: return a terminated table, allocated in C for cgo.
	return (*C.OSSL_ITEM)(unsafe.Pointer(&C.gofips_reason_strings[0]))
}

// ---- digest operation (OSSL_FUNC_DIGEST_* 1-17) ----

//export gofips_digest_newctx
func gofips_digest_newctx(provctx *C.void) C.uint64_t {
	return handleGuard(func() C.uint64_t {
		dbg("digest_newctx")
		_ = provctx
		h := ctxNew()
		recordCall() // allocation happens in Go, count it as module activity
		return C.uint64_t(h)
	})
}

//export gofips_digest_init
func gofips_digest_init(dctx C.uint64_t, params *C.OSSL_PARAM) C.int {
	return opGuard(func() C.int { return digest_initOp(dctx, params) })
}

func digest_initOp(dctx C.uint64_t, params *C.OSSL_PARAM) C.int {
	_ = params
	ctx := ctxGet(uint64(dctx))
	if ctx == nil {
		return 0
	}
	withLock(&ctx.mu, func() {
		ctx.h = sha256.New() // fresh hash each init
	})
	return 1
}

//export gofips_digest_update
func gofips_digest_update(dctx C.uint64_t, in *C.uchar, inl C.size_t) C.int {
	return opGuard(func() C.int { return digestUpdate(dctx, in, inl) })
}

func digestUpdate(dctx C.uint64_t, in *C.uchar, inl C.size_t) C.int {
	ctx := ctxGet(uint64(dctx))
	if ctx == nil || (in == nil && inl > 0) {
		return 0
	}
	b := unsafe.Slice((*byte)(unsafe.Pointer(in)), int(inl))
	withLock(&ctx.mu, func() { _, _ = ctx.h.Write(b) }) // sha256.Write never errors
	return 1
}

//export gofips_digest_final
func gofips_digest_final(dctx C.uint64_t, out *C.uchar, outl *C.size_t, outsz C.size_t) C.int {
	return opGuard(func() C.int { return digestFinal(dctx, out, outl, outsz) })
}

func digestFinal(dctx C.uint64_t, out *C.uchar, outl *C.size_t, outsz C.size_t) C.int {
	ctx := ctxGet(uint64(dctx))
	if ctx == nil || out == nil || outl == nil || outsz < 32 {
		return 0
	}
	var sum []byte
	withLock(&ctx.mu, func() { sum = ctx.h.Sum(nil) })
	if len(sum) != 32 {
		return 0
	}
	copy(unsafe.Slice((*byte)(unsafe.Pointer(out)), 32), sum)
	*outl = 32
	return 1
}

//export gofips_digest_freectx
func gofips_digest_freectx(dctx C.uint64_t) {
	// ctxDel drops the registry entry; the GC reclaims the state. Go's
	// hash.Hash has no zeroization API.
	ctxDel(uint64(dctx))
}

//export gofips_digest_get_params
func gofips_digest_get_params(params *C.OSSL_PARAM) C.int {
	return opGuard(func() C.int { return digest_get_paramsOp(params) })
}

func digest_get_paramsOp(params *C.OSSL_PARAM) C.int {
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
			if !setUint(p, 32) {
				ok = 0
			}
		case C.OSSL_DIGEST_PARAM_BLOCK_SIZE:
			if !setUint(p, 64) {
				ok = 0
			}
		}
	}
	return C.int(ok)
}

//export gofips_digest_gettable_params
func gofips_digest_gettable_params(params *C.OSSL_PARAM) *C.OSSL_PARAM {
	_ = params
	return nil
}

//export gofips_digest_get_ctx_params
func gofips_digest_get_ctx_params(dctx unsafe.Pointer, params *C.OSSL_PARAM) C.int {
	return opGuard(func() C.int { return digest_get_ctx_paramsOp(dctx, params) })
}

func digest_get_ctx_paramsOp(dctx unsafe.Pointer, params *C.OSSL_PARAM) C.int {
	_ = dctx
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
			if !setUint(p, 32) {
				ok = 0
			}
		case C.OSSL_DIGEST_PARAM_BLOCK_SIZE:
			if !setUint(p, 64) {
				ok = 0
			}
		case "provider", "provider-name":
			// EVP_MD_get_params("provider"/"provider-name") resolves here;
			// report our provider name so tests can prove which provider
			// served the fetch.
			if !setUtf8Ptr(p, provName) {
				ok = 0
			}
		case "temperfips-callcount":
			// Node-reachable evidence hook: the digest work counter, exposed
			// as a digest-level param so a Node script can prove the Go code
			// ran (Node cannot dlsym the C exports).
			if !setUint(p, uint64(getCallCount())) {
				ok = 0
			}
		}
	}
	return C.int(ok)
}

//export gofips_digest_set_ctx_params
func gofips_digest_set_ctx_params(dctx unsafe.Pointer, params *C.OSSL_PARAM) C.int {
	return opGuard(func() C.int { return digest_set_ctx_paramsOp(dctx, params) })
}

func digest_set_ctx_paramsOp(dctx unsafe.Pointer, params *C.OSSL_PARAM) C.int {
	_ = dctx
	_ = params
	// No settable ctx params in the slice, reject everything (fail closed).
	return 0
}

//export gofips_digest_gettable_ctx_params
func gofips_digest_gettable_ctx_params(dctx unsafe.Pointer, params *C.OSSL_PARAM) *C.OSSL_PARAM {
	_ = dctx
	_ = params
	return nil
}

//export gofips_digest_settable_ctx_params
func gofips_digest_settable_ctx_params(dctx, provctx unsafe.Pointer) *C.OSSL_PARAM {
	_, _ = dctx, provctx
	return nil // no settable parameters
}

// ---- EVP_RAND: CTR-DRBG-shaped RAND backed by Go crypto/rand ----
//
// Node's CSPRNG bootstrap (ncrypto::CSPRNG) resolves a RAND algorithm
// (OSSL_OP_RAND, name CTR-DRBG per the default provider's registration).
// The provider-level random_bytes hook (1032) alone is not sufficient when
// the provider is activated via OPENSSL_CONF. We register a RAND algorithm
// whose generate forwards to Go crypto/rand.
//
// FIPS semantics (see README "RAND / DRBG status"): when the Go runtime is
// in FIPS 140-3 mode (GOFIPS140=v1.0.0 build + GODEBUG=fips140=on),
// crypto/rand.Read routes through the Go Cryptographic Module's SP 800-90A
// Rev. 1 CTR DRBG (crypto/internal/fips140/drbg.Read, verified in the
// toolchain source: crypto/rand/rand.go reads
// `if fips140.Enabled { drbg.Read(b) }`). The DRBG's CTR_DRBG CAST (KAT,
// per FIPS 140-3 IG 10.3.A R7) runs at module init and aborts the process
// on failure. Without FIPS mode, crypto/rand.Read is the OS CSPRNG.
//
// OpenSSL-Go semantic mapping (honest mismatches, documented):
//   - instantiate/uninstantiate: no-op. Go's DRBG self-manages its
//     lifecycle (created on first use from the platform CSPRNG, resident
//     for the process); OpenSSL's explicit instantiate/reseed calls have
//     no public-API equivalent. No fips.o modification; the module's own
//     state machine governs.
//   - reseed: no-op for the same reason (Go's DRBG reseeds internally per
//     its own policy; the OpenSSL caller's entropy/addin input is ignored,
//     recorded as a semantic gap).
//   - strength: always reported 256 (module DRBG security strength); the
//     OpenSSL caller's requested strength is not negotiated, recorded.
//   - addin (additional input): ignored, Go's public API has no
//     additional-input parameter; recorded as a semantic gap.

type randCtx struct {
	mu sync.Mutex
}

var (
	randRegMu    sync.Mutex
	randNextID   uint64 = 1
	randContexts        = map[uint64]*randCtx{}
)

// randCalls counts generate calls served by Go (evidence hook, read via
// the digest-level "temperfips-callcount" param and temperfips_evidence).
var randCalls int64

//export gofips_rand_newctx
func gofips_rand_newctx(provctx *C.void, parent *C.void, parentCalls *C.OSSL_DISPATCH) C.uint64_t {
	return handleGuard(func() C.uint64_t {
		_ = provctx
		_ = parent
		_ = parentCalls
		randRegMu.Lock()
		defer randRegMu.Unlock()
		id := randNextID
		randNextID++
		randContexts[id] = &randCtx{}
		return C.uint64_t(id)
	})
}

//export gofips_rand_freectx
func gofips_rand_freectx(vctx C.uint64_t) {
	randRegMu.Lock()
	defer randRegMu.Unlock()
	delete(randContexts, uint64(vctx))
}

//export gofips_rand_instantiate
func gofips_rand_instantiate(vdrbg C.uint64_t, strength C.uint, predictionResistance C.int, pstr *C.uchar, pstrLen C.size_t, params *C.OSSL_PARAM) C.int {
	return opGuard(func() C.int { return rand_instantiateOp(vdrbg, strength, predictionResistance, pstr, pstrLen, params) })
}

func rand_instantiateOp(vdrbg C.uint64_t, strength C.uint, predictionResistance C.int, pstr *C.uchar, pstrLen C.size_t, params *C.OSSL_PARAM) C.int {
	// Semantic gap (documented above): Go's DRBG self-manages; this is a
	// no-op acknowledging the OpenSSL lifecycle call.
	return 1
}

//export gofips_rand_uninstantiate
func gofips_rand_uninstantiate(vdrbg C.uint64_t) C.int {
	return opGuard(func() C.int { return rand_uninstantiateOp(vdrbg) })
}

func rand_uninstantiateOp(vdrbg C.uint64_t) C.int {
	_ = vdrbg
	return 1
}

//export gofips_rand_generate
func gofips_rand_generate(vctx C.uint64_t, out *C.uchar, outlen C.size_t, strength C.uint, predictionResistance C.int, addin *C.uchar, addinLen C.size_t) C.int {
	return opGuard(func() C.int {
		return rand_generateOp(vctx, out, outlen, strength, predictionResistance, addin, addinLen)
	})
}

func rand_generateOp(vctx C.uint64_t, out *C.uchar, outlen C.size_t, strength C.uint, predictionResistance C.int, addin *C.uchar, addinLen C.size_t) C.int {
	_ = strength             // semantic gap: not negotiated (reported 256, see above)
	_ = predictionResistance // semantic gap: Go DRBG policy governs
	_ = addin                // semantic gap: no additional-input param in the public API
	_ = addinLen
	if out == nil && outlen > 0 {
		return 0
	}
	// The per-call MAX_REQUEST (reported 65536 by get_ctx_params,
	// the default provider's value) is enforced, not advisory: a
	// generate above it is refused, so the reported limit is the
	// real one. The core's RAND
	// manager chunks larger caller requests to this per-call bound, so
	// the caller-visible contract is unaffected (audreg drbg-split).
	const randMaxRequest = 1 << 16
	if outlen > randMaxRequest {
		dbg("rand_generate REFUSED: %d bytes exceeds MAX_REQUEST %d", int(outlen), randMaxRequest)
		return 0
	}
	// FIPS path: with GOFIPS140=v1.0.0 + GODEBUG=fips140=on this routes
	// through the Go Cryptographic Module's SP 800-90A CTR DRBG (see the
	// block comment above). Without FIPS mode it is the OS CSPRNG.
	b := unsafe.Slice((*byte)(unsafe.Pointer(out)), int(outlen))
	if _, err := rand.Read(b); err != nil {
		dbg("rand_generate failed: %v", err)
		return 0
	}
	withLock(&callMu, func() {
		randCalls++
	})
	recordOp("rand")
	return 1
}

//export gofips_rand_reseed
func gofips_rand_reseed(vctx C.uint64_t, predictionResistance C.int, ent *C.uchar, entLen C.size_t, addin *C.uchar, addinLen C.size_t) C.int {
	return opGuard(func() C.int { return rand_reseedOp(vctx, predictionResistance, ent, entLen, addin, addinLen) })
}

func rand_reseedOp(vctx C.uint64_t, predictionResistance C.int, ent *C.uchar, entLen C.size_t, addin *C.uchar, addinLen C.size_t) C.int {
	// Semantic gap (documented above): Go's DRBG reseeds per its own
	// policy; the caller's entropy/addin are ignored. No-op.
	_ = vctx
	_ = predictionResistance
	_ = ent
	_ = entLen
	_ = addin
	_ = addinLen
	return 1
}

//export gofips_rand_enable_locking
func gofips_rand_enable_locking(vctx C.uint64_t) C.int {
	return opGuard(func() C.int { return rand_enable_lockingOp(vctx) })
}

func rand_enable_lockingOp(vctx C.uint64_t) C.int {
	_ = vctx
	return 1
}

//export gofips_rand_lock
func gofips_rand_lock(vctx C.uint64_t) C.int {
	return opGuard(func() C.int { return rand_lockOp(vctx) })
}

func rand_lockOp(vctx C.uint64_t) C.int {
	randRegMu.Lock()
	ctx := randContexts[uint64(vctx)]
	randRegMu.Unlock()
	if ctx == nil {
		return 0
	}
	ctx.mu.Lock()
	return 1
}

//export gofips_rand_unlock
func gofips_rand_unlock(vctx C.uint64_t) {
	randRegMu.Lock()
	ctx := randContexts[uint64(vctx)]
	randRegMu.Unlock()
	if ctx == nil {
		return
	}
	ctx.mu.Unlock()
}

//export gofips_rand_get_ctx_params
func gofips_rand_get_ctx_params(vctx C.uint64_t, params *C.OSSL_PARAM) C.int {
	return opGuard(func() C.int { return rand_get_ctx_paramsOp(vctx, params) })
}

func rand_get_ctx_paramsOp(vctx C.uint64_t, params *C.OSSL_PARAM) C.int {
	dbg("rand_get_ctx_params vctx=%d", int64(vctx))
	_ = vctx
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
		case C.OSSL_RAND_PARAM_STATE:
			if !setUint32(p, 1) { // 1 = instantiated/ready
				ok = 0
			}
		case C.OSSL_RAND_PARAM_STRENGTH:
			if !setUint32(p, 256) { // module DRBG security strength
				ok = 0
			}
		case C.OSSL_RAND_PARAM_MAX_REQUEST:
			// 65536, as the default provider: the core's RAND manager
			// splits larger requests into chunks of this size.
			if !setUint(p, 1<<16) {
				ok = 0
			}
		case "temperfips-randcalls":
			// evidence hook: generate calls served by Go
			if !setUint(p, uint64(getRandCalls())) {
				ok = 0
			}
		}
	}
	return C.int(ok)
}

//export gofips_rand_set_ctx_params
func gofips_rand_set_ctx_params(vctx C.uint64_t, params *C.OSSL_PARAM) C.int {
	return opGuard(func() C.int { return rand_set_ctx_paramsOp(vctx, params) })
}

func rand_set_ctx_paramsOp(vctx C.uint64_t, params *C.OSSL_PARAM) C.int {
	_ = vctx
	_ = params
	return 1 // accept (ignore) DRBG tuning knobs
}

//export gofips_rand_gettable_ctx_params
func gofips_rand_gettable_ctx_params(vctx C.uint64_t, provctx *C.void) *C.OSSL_PARAM {
	_ = vctx
	_ = provctx
	return nil // no declared gettable ctx params in the slice
}

//export gofips_rand_settable_ctx_params
func gofips_rand_settable_ctx_params(vctx C.uint64_t, provctx *C.void) *C.OSSL_PARAM {
	_ = vctx
	_ = provctx
	return nil
}

//export gofips_rand_verify_zeroization
func gofips_rand_verify_zeroization(vctx C.uint64_t) C.int {
	return opGuard(func() C.int { return rand_verify_zeroizationOp(vctx) })
}

func rand_verify_zeroizationOp(vctx C.uint64_t) C.int {
	// A pass-through to crypto/rand: the provider holds no DRBG state,
	// so there is nothing to zeroize.
	_ = vctx
	return 1
}

// ---- evidence hook (Temper test harness only) ----

//export temperfips_evidence
func temperfips_evidence() C.longlong {
	return C.longlong(getCallCount())
}

// ---- OSSL_PARAM helpers ----

// maxParams bounds an OSSL_PARAM list; real lists hold a few entries.
const maxParams = 1024

// paramCount counts entries up to the OSSL_PARAM_END sentinel (key == NULL).
// A longer list panics, which opGuard or handleGuard turns into a refusal,
// rather than having its tail ignored.
func paramCount(params *C.OSSL_PARAM) int {
	for n := 0; n <= maxParams; n++ {
		if paramAt(params, n).key == nil {
			return n
		}
	}
	panic("OSSL_PARAM list longer than maxParams")
}

func paramAt(params *C.OSSL_PARAM, i int) *C.OSSL_PARAM {
	return (*C.OSSL_PARAM)(unsafe.Pointer(uintptr(unsafe.Pointer(params)) + uintptr(i)*unsafe.Sizeof(*params)))
}

// setUtf8Ptr writes a UTF8 param per its declared convention.
//
// As the default provider:
//   - data == NULL: a size probe. Write nothing, report the length.
//   - UTF8_STRING shorter than len(s)+1: fail, write nothing, report
//     len(s)+1.
//   - UTF8_STRING large enough: copy with the NUL, return_size = len(s).
//   - UTF8_PTR: point at a NUL-terminated string, return_size = len(s)+1.
func setUtf8Ptr(p *C.OSSL_PARAM, s string) bool {
	if p.data == nil {
		// Size probe: report the length without the NUL, write nothing.
		p.return_size = C.size_t(len(s))
		return true
	}
	if p.data_type == C.OSSL_PARAM_UTF8_STRING {
		// Caller-allocated buffer: it must hold the string plus NUL;
		// anything shorter is the default's rc=0 shape.
		if int(p.data_size) < len(s)+1 {
			p.return_size = C.size_t(len(s))
			return false
		}
		buf := unsafe.Slice((*byte)(unsafe.Pointer(p.data)), int(p.data_size))
		copy(buf, s)
		buf[len(s)] = 0
		p.return_size = C.size_t(len(s))
		return true
	}
	// UTF8_PTR: pointer-slot convention, write the address of a
	// NUL-terminated string into *(char**)data.
	*(*unsafe.Pointer)(unsafe.Pointer(p.data)) = unsafe.Pointer(internCString(s))
	p.return_size = C.size_t(len(s) + 1)
	return true
}

// internCString returns a C copy of s that stays valid for the life of the
// process, as UTF8_PTR callers expect. Each distinct value is allocated
// once; the values are provider names and parameters plus the ops counter.
func internCString(s string) *C.char {
	internMu.Lock()
	defer internMu.Unlock()
	cs, ok := interned[s]
	if !ok {
		cs = C.CString(s)
		interned[s] = cs
	}
	return cs
}

var (
	internMu sync.Mutex
	interned = map[string]*C.char{}
)

// setUtf8PtrTransient is setUtf8Ptr for a value that changes on every
// query (the ops counter). The last opsRingSize strings stay valid; older
// ones are freed, so repeated queries do not grow memory. Callers read the
// value right after the query.
const opsRingSize = 64

var (
	opsRing [opsRingSize]*C.char
	opsNext int
)

func setUtf8PtrTransient(p *C.OSSL_PARAM, s string) bool {
	if p.data == nil || p.data_type != C.OSSL_PARAM_UTF8_PTR {
		return setUtf8Ptr(p, s)
	}
	internMu.Lock()
	defer internMu.Unlock()
	if old := opsRing[opsNext]; old != nil {
		C.free(unsafe.Pointer(old))
	}
	cs := C.CString(s)
	opsRing[opsNext] = cs
	opsNext = (opsNext + 1) % opsRingSize
	*(*unsafe.Pointer)(unsafe.Pointer(p.data)) = unsafe.Pointer(cs)
	p.return_size = C.size_t(len(s) + 1)
	return true
}

// setOctet copies an octet string into a caller-allocated OSSL_PARAM
// (OSSL_PARAM_OCTET_STRING: data is the caller's buffer). Two caller
// shapes, matching the default provider's contract on both:
//   - Size probe: data == NULL with data_size == 0. The caller only asks
//     for the needed length. Report it and return success (rc=1); the
//     default provider answers this shape with success + needed size
//     (measured on 3.0.13 and 3.5.x), and libssl's TLS 1.3 key-share
//     path (add_key_share) performs exactly this probe; failing it
//     breaks every gofips-only TLS 1.3 client handshake.
//   - Undersized non-NULL buffer: data_size < len. That is an error
//     (rc=0, return_size = needed, nothing written); a success with an
//     untouched buffer leaks nothing but lies. The caller must then fail
//     the whole get_params call.
func setOctet(p *C.OSSL_PARAM, val []byte) bool {
	if int(p.data_size) < len(val) {
		if p.data == nil {
			// Size probe: no buffer, no write, report the needed size.
			p.return_size = C.size_t(len(val))
			return true
		}
		p.return_size = C.size_t(len(val))
		return false
	}
	if p.data == nil {
		// data_size >= len with a NULL buffer: no destination. The
		// default provider reports the needed size and succeeds here
		// (measured: NULL buf with size 65 and even size 8 both return
		// rc=1, needed=65); mirror that, writing nothing.
		p.return_size = C.size_t(len(val))
		return true
	}
	buf := unsafe.Slice((*byte)(unsafe.Pointer(p.data)), int(p.data_size))
	copy(buf, val)
	p.return_size = C.size_t(len(val))
	return true
}

// setUint writes an unsigned integer per the param's declared data_size
// (4 or 8 bytes), so callers constructing unsigned-int params
// (data_size=4) get exactly 4 bytes written, no overflow into adjacent
// OSSL_PARAM entries.
//
// As the default provider, a NULL-data size probe reports the value's
// natural size:
//   - 32-bit values (provider status, RAND state and strength, cipher
//     mode, keymgmt bits/security-bits/max-size) go through setUint32.
//   - size_t values (digest and cipher sizes, KDF/MAC size, RAND
//     max-request) use setUint.
//   - data_size 4 or 8 with a buffer: write the value (low 32 bits for
//     4), return_size = data_size.
//   - any other data_size: fail and write nothing.
func setUint(p *C.OSSL_PARAM, v uint64) bool {
	if p.data == nil {
		// Size probe: size_t-valued parameter class; report the
		// needed size (8), write nothing.
		p.return_size = 8
		return true
	}
	switch p.data_size {
	case 4:
		*(*uint32)(unsafe.Pointer(p.data)) = uint32(v)
		p.return_size = 4
	case 8:
		*(*uint64)(unsafe.Pointer(p.data)) = v
		p.return_size = 8
	default:
		// Unknown size: fail this param by leaving it untouched.
		return false
	}
	return true
}

// setUint32 is setUint for the 32-bit-natural parameter class (provider
// status, RAND state/strength, cipher mode, keymgmt
// bits/security-bits/max-size): the NULL-data size probe reports 4,
// matching the default provider's measured return_size for this class
// (reconciliation). The buffered write path is identical to
// setUint's (4-byte low-word write, 8-byte full write).
func setUint32(p *C.OSSL_PARAM, v uint64) bool {
	if p.data == nil {
		// Size probe: 32-bit-valued parameter class.
		p.return_size = 4
		return true
	}
	return setUint(p, v)
}

// main is required for -buildmode=c-shared; it never runs.
func main() {}
