// Command fipsmode reports the Go Cryptographic Module's runtime mode for
// the integrity and DRBG records (E-08, E-09). In FIPS mode, crypto/rand
// reads come from the module's SP 800-90A CTR DRBG, and the module's
// integrity check and self-tests run at init; a failure aborts the process.
//
//	GOFIPS140=v1.0.0 go build -o /tmp/fipsmode ./testdata/fipsmode
//	GODEBUG=fips140=on /tmp/fipsmode
//	GODEBUG=fips140=off /tmp/fipsmode
package main

import (
	"crypto/fips140"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"os"
)

func main() {
	fmt.Printf("fips140.Enabled: %v\n", fips140.Enabled())
	for _, n := range []int{1, 32, 4096, 1 << 20} {
		if _, err := rand.Read(make([]byte, n)); err != nil {
			fmt.Printf("rand.Read(%d): %v\n", n, err)
			os.Exit(1)
		}
	}
	fmt.Println("rand.Read at 1B/32B/4KiB/1MiB: ok")
	fmt.Printf("sha256(abc): %x\n", sha256.Sum256([]byte("abc")))
}
