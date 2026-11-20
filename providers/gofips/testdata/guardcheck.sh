#!/usr/bin/env bash
# guardcheck.sh - classify every export wired in dispatch.c:
#   - opGuard-wrapped: returns C.int and its first body line delegates to
#     opGuard (a panic becomes a refusal);
#   - pointer/handle/void: returns a pointer, a C.uint64_t handle or
#     nothing; a handle's first body line must delegate to handleGuard;
#   - C-implemented: defined in dispatch.c (TLS capability callbacks);
#   - MISSING: no Go function and no C definition. Fails the check: a
#     wired NULL is a load-time segfault.
# UNGUARDED C.int and handle exports are reported with file and line and
# fail the check.
# usage: guardcheck.sh <repo-root>
#       guardcheck.sh --selftest   (classifier fixtures, no repo needed)
set -uo pipefail

# --selftest: synthetic extern/definition shapes, so a regex regression
# fails here instead of silently reclassifying exports (e.g.
# `extern void *fn(` matching as a C definition).
if [ "${1:-}" = "--selftest" ]; then
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' EXIT
  mkdir -p "$tmp/providers/gofips"
  cp "$0" "$tmp/guardcheck.sh"
  cat > "$tmp/providers/gofips/dispatch.c" <<'GCEOF'
extern void *gofips_cipher_newctx(void *provctx);
extern void*gofips_nospace_newctx(void *provctx);
extern int gofips_kdf_derive(void *kctx, unsigned char *out, size_t *outl);
extern const OSSL_PARAM *gofips_kdf_gettable_params(void *provctx);
extern const OSSL_DISPATCH *gofips_query_operation(void *provctx, int op);
static int gofips_tls_caps_c(void *provctx, const char *capability,
                             OSSL_CALLBACK *cb, void *cbarg) {
    (void)provctx;
    return 0;
}
{OSSL_FUNC_DIGEST_NEWCTX, (OSSL_FUNC)gofips_cipher_newctx},
{OSSL_FUNC_DIGEST_INIT, (OSSL_FUNC)gofips_nospace_newctx},
{OSSL_FUNC_KDF_DERIVE, (OSSL_FUNC)gofips_kdf_derive},
{OSSL_FUNC_KDF_GETTABLE_PARAMS, (OSSL_FUNC)gofips_kdf_gettable_params},
{OSSL_FUNC_PROVIDER_QUERY_OPERATION, (OSSL_FUNC)gofips_query_operation},
{OSSL_FUNC_PROVIDER_GET_CAPABILITIES, (OSSL_FUNC)gofips_tls_caps_c},
{OSSL_FUNC_KEYEXCH_INIT, (OSSL_FUNC)gofips_gone_from_go},
{OSSL_FUNC_MAC_INIT, (OSSL_FUNC)gofips_unguarded_shape},
{OSSL_FUNC_MAC_DUPCTX, (OSSL_FUNC)gofips_unguarded_handle},
{0, NULL},
GCEOF
  cat > "$tmp/providers/gofips/provider.go" <<'GCEOF'
package main

//export gofips_cipher_newctx
func gofips_cipher_newctx(provctx *C.void) C.uint64_t {
	return handleGuard(func() C.uint64_t { return 0 })
}

//export gofips_nospace_newctx
func gofips_nospace_newctx(provctx *C.void) C.uint64_t {
	return handleGuard(func() C.uint64_t { return 0 })
}

//export gofips_kdf_derive
func gofips_kdf_derive(kctx C.uint64_t, out *C.uchar, outl *C.size_t) C.int {
	return opGuard(func() C.int { return 0 })
}

//export gofips_kdf_gettable_params
func gofips_kdf_gettable_params(provctx *C.void) *C.OSSL_PARAM { return nil }

//export gofips_query_operation
func gofips_query_operation(provctx *C.void, op C.int) *C.OSSL_ALGORITHM { return nil }

//export gofips_gone_from_go
// MISSING shape: wired, but no Go function and no C definition.
GCEOF
  cat > "$tmp/providers/gofips/tls.go" <<'GCEOF'
package main

//export gofips_unguarded_shape
func gofips_unguarded_shape(mctx C.uint64_t) C.int {
	// UNGUARDED shape: a C.int export whose first body line does not
	// delegate through the panic boundary.
	return 0
}

//export gofips_unguarded_handle
func gofips_unguarded_handle(mctx C.uint64_t) C.uint64_t {
	return mctx
}
GCEOF
  out=$(bash "$tmp/guardcheck.sh" "$tmp")
  echo "$out"
  # extern declarations (with or without a space before the name) are
  # Go-implemented: 2 newctx + gettable + query + unguarded handle = 5
  # pointer class.
  echo "$out" | grep -q "5 pointer/handle/void class" || { echo "SELFTEST FAIL: pointer extern misclassified"; exit 1; }
  # only the derive counts as wrapped; the unguarded shape must not.
  echo "$out" | grep -q "1 opGuard-wrapped C.int" || { echo "SELFTEST FAIL: C.int exports misclassified"; exit 1; }
  # the static definition in dispatch.c is the one C-implemented export.
  echo "$out" | grep -q "1 C-implemented (dispatch.c)" || { echo "SELFTEST FAIL: real C definition misclassified"; exit 1; }
  echo "$out" | grep -q "MISSING: gofips_gone_from_go" || { echo "SELFTEST FAIL: missing export not detected"; exit 1; }
  echo "$out" | grep -q "UNGUARDED C.int: gofips_unguarded_shape" || { echo "SELFTEST FAIL: unguarded C.int not reported"; exit 1; }
  echo "$out" | grep -q "UNGUARDED handle: gofips_unguarded_handle" || { echo "SELFTEST FAIL: unguarded handle not reported"; exit 1; }
  echo "$out" | grep -q "UNGUARDED handle: gofips_cipher_newctx" && { echo "SELFTEST FAIL: guarded handle reported"; exit 1; }
  echo "GUARDCHECK SELFTEST: ALL PASS"
  exit 0
fi

REPO="${1:?repo root}"
SRC="$REPO/providers/gofips"
wired=$(grep -oE '\(OSSL_FUNC\)(gofips_[a-z0-9_]+)' "$SRC/dispatch.c" | sed 's/(OSSL_FUNC)//' | sort -u)
total=0; guarded=0; ptrclass=0; missing=0; cimpl=0; unguarded=0
for fn in $wired; do
  total=$((total+1))
  # extern lines declare Go-implemented exports; any other
  # `type name(` line in dispatch.c is a C definition. --selftest pins
  # both shapes.
  if grep -qE "^extern [A-Za-z_][A-Za-z0-9_ ()*]*\**$fn\(" "$SRC/dispatch.c"; then
    : # an extern declaration: the implementation is in Go
  elif grep -qE "^(static )?[A-Za-z_][A-Za-z0-9_ ()*]*\**$fn\(" "$SRC/dispatch.c"; then
    cimpl=$((cimpl+1))
    continue
  fi
  sig=$(grep -h "^func $fn(" $(ls "$SRC"/*.go | grep -v _test.go) 2>/dev/null | head -1)
  if [ -z "$sig" ]; then
    echo "MISSING: $fn (wired in dispatch.c, no Go function)"
    missing=$((missing+1))
    continue
  fi
  if echo "$sig" | grep -q ") C.int {"; then
    # C.int return: the next line must call opGuard
    line=$(grep -n "^func $fn(" $(ls "$SRC"/*.go | grep -v _test.go) 2>/dev/null | head -1 | cut -d: -f2)
    file=$(grep -ln "^func $fn(" $(ls "$SRC"/*.go | grep -v _test.go) 2>/dev/null | head -1)
    next=$(sed -n "$((line+1))p" "$file")
    if echo "$next" | grep -q "opGuard"; then
      guarded=$((guarded+1))
    else
      echo "UNGUARDED C.int: $fn ($file:$line)"
      unguarded=$((unguarded+1))
    fi
  else
    ptrclass=$((ptrclass+1))
    if echo "$sig" | grep -q ") C.uint64_t {"; then
      line=$(grep -n "^func $fn(" $(ls "$SRC"/*.go | grep -v _test.go) 2>/dev/null | head -1 | cut -d: -f2)
      file=$(grep -ln "^func $fn(" $(ls "$SRC"/*.go | grep -v _test.go) 2>/dev/null | head -1)
      if ! sed -n "$((line+1))p" "$file" | grep -q "handleGuard"; then
        echo "UNGUARDED handle: $fn ($file:$line)"
        unguarded=$((unguarded+1))
      fi
    fi
  fi
done
echo "GUARDCHECK: $total wired exports: $guarded opGuard-wrapped C.int, $ptrclass pointer/handle/void class, $cimpl C-implemented (dispatch.c), $missing missing"
[ "$missing" -eq 0 ] && [ "$unguarded" -eq 0 ] || exit 1
