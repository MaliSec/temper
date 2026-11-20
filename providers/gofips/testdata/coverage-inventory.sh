#!/usr/bin/env bash
# coverage-inventory.sh - enumerate every export wired in dispatch.c,
# group by family, and diff against panictest-inventory.txt. Exits 1 on
# drift. coverage-check.sh then checks panictest.c covers each family.
# Regenerate: INVENTORY_WRITE=1 bash coverage-inventory.sh
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
PROV="$HERE/.."
REPO="$(cd "$PROV/../.." && pwd)"

enumerate() {
python3 - "$PROV" <<'PYEOF'
import re, sys
prov = sys.argv[1]
src = open(prov + '/dispatch.c').read()
wired = sorted(set(re.findall(r'\(OSSL_FUNC\)(gofips_\w+)', src)))
fam = {}
def family(name):
    if name.startswith('gofips_digest1'): return 'digest-sha1'
    if name.startswith('gofips_digest384'): return 'digest-sha384'
    if name.startswith('gofips_digest512'): return 'digest-sha512'
    if name.startswith('gofips_digest'): return 'digest-sha256'
    if name.startswith('gofips_mac'): return 'mac'
    if name.startswith('gofips_kdf'): return 'kdf'
    if name.startswith('gofips_tls13kdf'): return 'tls13kdf'
    if name.startswith('gofips_cipher128'): return 'cipher-128'
    if name.startswith('gofips_cbc'): return 'cipher-cbc'
    if name.startswith('gofips_cipher'): return 'cipher-gcm256'
    if name.startswith('gofips_keymgmt'): return 'keymgmt'
    if name.startswith('gofips_keyexch'): return 'keyexch'
    if name.startswith('gofips_sig'): return 'sig'
    if name.startswith('gofips_sha3') or name.startswith('gofips_shake'): return 'sha3'
    if name.startswith('gofips_pbkdf2'): return 'pbkdf2'
    if name.startswith('gofips_tls1prf'): return 'tls1prf'
    if name.startswith('gofips_rsa_keymgmt') or name.startswith('gofips_rsa_pss_keymgmt'): return 'rsa-keymgmt'
    if name.startswith('gofips_rsa_sig'): return 'rsa-sig'
    if name.startswith('gofips_hmac_keymgmt'): return 'hmac-keymgmt'
    if name.startswith('gofips_hmac_sig'): return 'hmac-sig'
    if name.startswith('gofips_rand'): return 'rand'
    if name.startswith('gofips_random_bytes'): return 'rand'
    if name.startswith('gofips_get') or name.startswith('gofips_query') or name.startswith('gofips_unquery') or name.startswith('gofips_teardown'): return 'provider'
    return 'other:' + name
for w in wired:
    fam.setdefault(family(w), []).append(w)
for f in sorted(fam):
    print(f'{f}: {len(fam[f])} exports')
    for w in fam[f]:
        print(f'  {w}')
PYEOF
}

fresh="$(enumerate)"

if [ "${INVENTORY_WRITE:-0}" = "1" ]; then
  printf '%s\n' "$fresh" > "$HERE/panictest-inventory.txt"
  echo "INVENTORY: regenerated panictest-inventory.txt from the current dispatch surface"
  exit 0
fi

if ! printf '%s\n' "$fresh" | diff -u "$HERE/panictest-inventory.txt" - > "$HERE/.drift.$$" 2>&1; then
  echo "INVENTORY DRIFT: panictest-inventory.txt does not match the current dispatch surface:"
  cat "$HERE/.drift.$$"
  rm -f "$HERE/.drift.$$"
  echo "Fix: INVENTORY_WRITE=1 bash coverage-inventory.sh, commit, re-run."
  exit 1
fi
rm -f "$HERE/.drift.$$"
echo "INVENTORY: panictest-inventory.txt matches the current dispatch surface"
