//go:build gofips_debug

package main

// debugEnabled override for debug builds only: built with
// -tags gofips_debug, this file sets the flag true so GOFIPS_DEBUG=1 at
// runtime emits the trace. Release builds (no tag) keep the compiled-out
// default (debugEnabled=false in provider.go): no secret material can
// reach stderr from a release artifact.
func init() { debugEnabled = true }
