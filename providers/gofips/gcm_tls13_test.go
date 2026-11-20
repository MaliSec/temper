package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"testing"
)

var (
	testKey = bytes.Repeat([]byte{0x11}, 32)
	testIV  = []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	testAAD = []byte{23, 3, 3, 0, 30}
)

// recordNonce is what libssl computes for a TLS 1.3 record: IV XOR seq.
func recordNonce(seq uint64) []byte {
	n := append([]byte(nil), testIV...)
	var s [8]byte
	binary.BigEndian.PutUint64(s[:], seq)
	for i := range s {
		n[4+i] ^= s[i]
	}
	return n
}

// The module refuses a repeated record counter on its own, with the
// adapter's check out of the picture: this calls the crypto/tls hook
// directly.
func TestModuleRefusesRepeatedCounter(t *testing.T) {
	a := aeadAESGCMTLS13(testKey, testIV)
	seq := func(n uint64) []byte { var s [8]byte; binary.BigEndian.PutUint64(s[:], n); return s[:] }
	a.Seal(nil, seq(0), []byte("record 0"), testAAD)
	a.Seal(nil, seq(1), []byte("record 1"), testAAD)
	for _, n := range []uint64{1, 0} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("module sealed record counter %d a second time", n)
				}
			}()
			a.Seal(nil, seq(n), []byte("replay"), testAAD)
		}()
	}
}

func TestSealRefusals(t *testing.T) {
	g := newTLS13GCM(testKey)
	if _, err := g.Seal(recordNonce(0), []byte("r0"), testAAD); err != nil {
		t.Fatalf("first seal: %v", err)
	}
	if _, err := g.Seal(recordNonce(0), []byte("r0"), testAAD); !errors.Is(err, errTLS13Counter) {
		t.Errorf("same nonce again: got %v, want errTLS13Counter", err)
	}
	if _, err := g.Seal(recordNonce(5), []byte("r5"), testAAD); err != nil {
		t.Errorf("a gap in the counter must be accepted: %v", err)
	}
	if _, err := g.Seal(recordNonce(3), []byte("r3"), testAAD); !errors.Is(err, errTLS13Counter) {
		t.Errorf("earlier counter: got %v, want errTLS13Counter", err)
	}
	other := recordNonce(6)
	other[0] ^= 0x80
	if _, err := g.Seal(other, []byte("x"), testAAD); !errors.Is(err, errTLS13Nonce) {
		t.Errorf("different prefix: got %v, want errTLS13Nonce", err)
	}
	if _, err := g.Seal(recordNonce(6)[:11], []byte("x"), testAAD); !errors.Is(err, errTLS13NonceSize) {
		t.Errorf("short nonce: got %v, want errTLS13NonceSize", err)
	}
	if _, err := g.Seal(recordNonce(6), []byte("r6"), testAAD); err != nil {
		t.Errorf("the next record after refusals: %v", err)
	}
	if g.broken {
		t.Error("instance marked broken by ordinary refusals")
	}
}

func TestOpen(t *testing.T) {
	enc, dec := newTLS13GCM(testKey), newTLS13GCM(testKey)
	var cts [][]byte
	for seq := uint64(0); seq < 4; seq++ {
		ct, err := enc.Seal(recordNonce(seq), []byte{byte(seq), 'p', 't'}, testAAD)
		if err != nil {
			t.Fatalf("seal %d: %v", seq, err)
		}
		cts = append(cts, ct)
	}
	for seq := uint64(0); seq < 4; seq++ {
		pt, err := dec.Open(recordNonce(seq), cts[seq], testAAD)
		if err != nil || !bytes.Equal(pt, []byte{byte(seq), 'p', 't'}) {
			t.Errorf("open %d: pt=%q err=%v", seq, pt, err)
		}
	}
	bad := append([]byte(nil), cts[1]...)
	bad[len(bad)-1] ^= 1
	if _, err := dec.Open(recordNonce(1), bad, testAAD); err == nil {
		t.Error("a wrong tag was accepted")
	}
	if _, err := dec.Open(recordNonce(1), cts[1], []byte("other aad")); err == nil {
		t.Error("wrong AAD was accepted")
	}
	if pt, err := dec.Open(recordNonce(2), cts[2], testAAD); err != nil || len(pt) != 3 {
		t.Errorf("open after failed opens: %v", err)
	}
}

// The TLS 1.3 path must produce exactly what the general GCM produces for
// the same key, nonce, AAD and plaintext. Under GODEBUG=fips140=only the
// general path is rejected by the module; that rejection is the point, and
// the comparison is skipped.
func TestMatchesGeneralGCM(t *testing.T) {
	block, err := aes.NewCipher(testKey)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := cipher.NewGCM(block)
	if err != nil {
		t.Skipf("general GCM unavailable (expected under fips140=only): %v", err)
	}
	g := newTLS13GCM(testKey)
	for seq := uint64(0); seq < 8; seq++ {
		pt := bytes.Repeat([]byte{byte(seq)}, int(seq)*37)
		got, err := g.Seal(recordNonce(seq), pt, testAAD)
		if err != nil {
			t.Fatalf("seal %d: %v", seq, err)
		}
		want := ref.Seal(nil, recordNonce(seq), pt, testAAD)
		if !bytes.Equal(got, want) {
			t.Errorf("record %d differs from the general GCM output", seq)
		}
	}
}
