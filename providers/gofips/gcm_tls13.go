package main

// AES-GCM through the Go Cryptographic Module's TLS 1.3 GCM service, which
// enforces the record counter inside the module, per key instance.
//
// cipher.NewGCM takes arbitrary nonces, which the Security Policy lists as
// non-approved for encryption. The module's NewGCMForTLS13 (SP 2.7) is not
// exported; crypto/tls keeps its constructor, aeadAESGCMTLS13, linkable
// (go.dev/issue/67401), and this file uses it.
//
// libssl passes each TLS 1.3 record's full nonce (static IV XOR sequence
// number). The first record's nonce is the static IV, so the adapter takes
// it as the mask and hands later records to the module as (mask, sequence
// number), as crypto/tls does.

import (
	"crypto/cipher"
	_ "crypto/tls" // provides aeadAESGCMTLS13
	"encoding/binary"
	"errors"
	"math"
	"sync"
	_ "unsafe" // go:linkname
)

// The return type inside crypto/tls is an unexported interface that embeds
// cipher.AEAD; its first four methods are the cipher.AEAD methods, in the
// same order, so the value is usable as a cipher.AEAD. Other users of this
// hook rely on the same layout.
//
//go:linkname aeadAESGCMTLS13 crypto/tls.aeadAESGCMTLS13
func aeadAESGCMTLS13(key, nonceMask []byte) cipher.AEAD

const (
	tls13NonceSize = 12
	tls13TagSize   = 16
)

// tls13GCM adapts the module's TLS 1.3 GCM to what the provider's cipher
// code needs: the full 12-byte nonce in, one Seal or Open per record, and
// an error (never a panic) on refusal. One instance holds one key in one
// direction.
//
// A provider ctx copy (dupctx) shares its instance with the original, so
// the module's counter covers both: a record number sealed through one
// cannot be sealed again through the other.
type tls13GCM struct {
	mu      sync.Mutex
	key     []byte      // held only until the first record fixes the mask
	aead    cipher.AEAD // the module's TLS 1.3 GCM, built on first use
	mask    [tls13NonceSize]byte
	next    uint64 // lowest sequence number still acceptable for Seal
	broken  bool   // a panic escaped the module call: refuse everything after
	retired bool   // the key moved to TLS 1.2 record mode: refuse TLS 1.3 records
}

func newTLS13GCM(key []byte) *tls13GCM {
	return &tls13GCM{key: append([]byte(nil), key...)}
}

func (t *tls13GCM) Overhead() int { return tls13TagSize }

// bind builds the module AEAD the first time a nonce is seen. That nonce
// becomes the mask: for TLS 1.3 it is the static IV (sequence number 0).
// The module makes the same assumption about its own first call.
func (t *tls13GCM) bind(nonce []byte) {
	if t.aead != nil {
		return
	}
	copy(t.mask[:], nonce)
	t.aead = aeadAESGCMTLS13(t.key, t.mask[:])
	for i := range t.key {
		t.key[i] = 0
	}
	t.key = nil
}

// used reports whether a record was sealed or opened under this key.
func (t *tls13GCM) used() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.aead != nil
}

// isRetired reports whether the key moved to TLS 1.2 record mode.
func (t *tls13GCM) isRetired() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.retired
}

// retire stops TLS 1.3 records under this key: one key serves one record
// mode, so a TLS 1.2 nonce can never repeat a TLS 1.3 one.
func (t *tls13GCM) retire() {
	withLock(&t.mu, func() {
		t.retired = true
	})
}

// seq recovers the 8-byte record sequence number from a full nonce. The
// first 4 bytes of a TLS 1.3 nonce never change for a key; a nonce whose
// prefix differs from the mask cannot be a record of this connection.
func (t *tls13GCM) seq(nonce []byte) (uint64, []byte, bool) {
	if len(nonce) != tls13NonceSize {
		return 0, nil, false
	}
	for i := 0; i < 4; i++ {
		if nonce[i] != t.mask[i] {
			return 0, nil, false
		}
	}
	var s [8]byte
	for i := range s {
		s[i] = nonce[4+i] ^ t.mask[4+i]
	}
	return binary.BigEndian.Uint64(s[:]), s[:], true
}

var (
	errTLS13NonceSize = errors.New("gofips: GCM nonce must be 12 bytes")
	errTLS13Nonce     = errors.New("gofips: GCM nonce does not belong to this key's record sequence")
	errTLS13Counter   = errors.New("gofips: GCM record counter did not increase (nonce reuse refused)")
	errTLS13Broken    = errors.New("gofips: TLS 1.3 GCM instance is unusable after an earlier failure")
)

// call runs one module operation. The crypto/tls wrapper mutates its mask
// around the call, so a panic from inside would leave it corrupted: if one
// escapes, the instance is marked broken and refuses everything afterwards.
func (t *tls13GCM) call(fn func()) (err error) {
	t.broken = true // cleared only if fn returns normally
	defer func() {
		if r := recover(); r != nil {
			err = errTLS13Broken
		}
	}()
	fn()
	t.broken = false
	return nil
}

// Seal encrypts one record and returns ciphertext followed by the tag.
//
// The counter check here mirrors the module's own. It exists so that an
// out-of-order nonce is refused with an error before the module call; the
// module would refuse it with a panic. The binding enforcement is still
// the module's: nothing reaches the wire without passing its check.
func (t *tls13GCM) Seal(nonce, plaintext, aad []byte) ([]byte, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.broken || t.retired {
		return nil, errTLS13Broken
	}
	if len(nonce) != tls13NonceSize {
		return nil, errTLS13NonceSize
	}
	t.bind(nonce)
	n, s, ok := t.seq(nonce)
	if !ok {
		return nil, errTLS13Nonce
	}
	if n == math.MaxUint64 || n < t.next {
		return nil, errTLS13Counter
	}
	var out []byte
	if err := t.call(func() { out = t.aead.Seal(nil, s, plaintext, aad) }); err != nil {
		return nil, err
	}
	t.next = n + 1
	return out, nil
}

// Open decrypts one record (ciphertext followed by the tag). Decryption
// needs no counter rule (a repeated nonce on Open reveals nothing); the
// nonce still has to fit the mask.
func (t *tls13GCM) Open(nonce, ciphertext, aad []byte) ([]byte, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.broken || t.retired {
		return nil, errTLS13Broken
	}
	if len(nonce) != tls13NonceSize {
		return nil, errTLS13NonceSize
	}
	t.bind(nonce)
	_, s, ok := t.seq(nonce)
	if !ok {
		return nil, errTLS13Nonce
	}
	var out []byte
	var openErr error
	if err := t.call(func() { out, openErr = t.aead.Open(nil, s, ciphertext, aad) }); err != nil {
		return nil, err
	}
	return out, openErr
}
