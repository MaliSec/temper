#!/usr/bin/env bash
# run-tls-bench.sh - TLS benchmark, native execution only (QEMU numbers are
# not performance data). Runs node-tls-bench.js in two containers:
#   - gofips-only config (default provider absent)
#   - control (no OPENSSL_CONF, stock providers)
# Both: TLS 1.3, ECDSA P-256 cert, AES-256-GCM-SHA384, prime256v1,
# SSL_OP_NO_TICKET.
#
# Usage: ./run-tls-bench.sh [node-image]
set -euo pipefail

DOCKER_ARCH=$(case "$(uname -m)" in aarch64) echo arm64 ;; *) echo amd64 ;; esac)
IMAGE="${1:-node:local-$DOCKER_ARCH}"
HERE="$(cd "$(dirname "$0")" && pwd)"
PROV="$HERE/../.."
WORK="$(mktemp -d "${TMPDIR:-/tmp}/gofips-bench-XXXXXX")"
chmod 755 "$WORK"
trap 'rm -rf "$WORK"' EXIT

# GOFIPS_SO: a provider to benchmark (the release's shipped gofips.so);
# without it, one is built from this tree.
if [ -n "${GOFIPS_SO:-}" ]; then
  echo "=== Provider: $GOFIPS_SO ==="
  cp "$GOFIPS_SO" "$WORK/temperfips.so"
else
  echo "=== Build provider (native $(uname -m)) ==="
  (cd "$PROV" && CGO_ENABLED=1 GOFIPS140=v1.0.0 \
    go build -buildvcs=false -ldflags=-checklinkname=0 -buildmode=c-shared -o "$WORK/temperfips.so" .)
fi
readelf -d "$WORK/temperfips.so" | grep NEEDED || true

echo "=== Stage configs + certs ==="
sed "s|GOFIPS_MODULE_PATH|/gofips/temperfips.so|" "$HERE/openssl-gofips.cnf" > "$WORK/openssl.cnf"
openssl ecparam -name prime256v1 -genkey -noout -out "$WORK/tls-key.pem" 2>/dev/null
openssl req -new -x509 -key "$WORK/tls-key.pem" -out "$WORK/tls-cert.pem" \
  -days 2 -subj "/CN=temper-gofips-bench" -sha256 2>/dev/null
chmod 644 "$WORK/tls-key.pem" "$WORK/tls-cert.pem"

echo "=== Control config: default provider active ==="

run_bench() {
  local label="$1"; shift
  local conf="$1"; shift
  echo "--- $label ---"
  docker run --rm \
    -v "$WORK:/gofips" \
    -v "$HERE:/test" \
    --security-opt label=disable \
    ${conf:+-e OPENSSL_CONF=/gofips/$conf} \
    -e GODEBUG=fips140=on \
    -e BENCH_ROUNDS="${BENCH_ROUNDS:-3}" \
    --entrypoint /usr/bin/node \
    "$IMAGE" /test/node-tls-bench.js 2>&1
}

echo
echo "=== GOFIPS-ONLY benchmark ==="
GOFIPS_OUT=$(run_bench "gofips-only" "openssl.cnf" | tee /dev/stderr | grep 'BENCH-JSON ' | tail -1 || true)

echo
echo "=== DEFAULT-PROVIDER CONTROL benchmark ==="
CONTROL_OUT=$(run_bench "default-provider control" "" | tee /dev/stderr | grep 'BENCH-JSON ' | tail -1 || true)

echo
echo "=== Summary (medians across rounds) ==="
python3 - <<PYEOF
import json, sys

def parse(line):
    if not line:
        return None
    return json.loads(line.split('BENCH-JSON ', 1)[1])

g = parse("""$GOFIPS_OUT""")
c = parse("""$CONTROL_OUT""")
if not g or not c:
    print("MISSING BENCH DATA (gofips=%s control=%s)" % (bool(g), bool(c)))
    sys.exit(1)

def rel(a, b):
    if a is None or b in (None, 0):
        return "n/a"
    return "%+.1f%%" % ((a - b) / b * 100)

rows = [
    ("serial handshake median (ms)", g["serial_median_ms"], c["serial_median_ms"]),
    ("serial handshake p95 (ms)", g["serial_p95_ms"], c["serial_p95_ms"]),
    ("serial handshakes/sec", g["serial_hs_per_sec"], c["serial_hs_per_sec"]),
    ("concurrent median (ms, c=%d)" % 20, g["concurrent_median_ms"], c["concurrent_median_ms"]),
    ("concurrent p95 (ms)", g["concurrent_p95_ms"], c["concurrent_p95_ms"]),
    ("concurrent handshakes/sec", g["concurrent_hs_per_sec"], c["concurrent_hs_per_sec"]),
    ("bulk echo MiB/s (16MiB bidirectional)", g["bulk_mib_per_sec"], c["bulk_mib_per_sec"]),
    ("process CPU total (ms, last round)", g["cpu_ms_total"], c["cpu_ms_total"]),
    ("peak RSS (kB)", g["peak_rss_kb"], c["peak_rss_kb"]),
]
print("%-42s %14s %14s %12s" % ("metric", "gofips", "control", "delta"))
for name, gv, cv in rows:
    print("%-42s %14s %14s %12s" % (name,
        ("%.2f" % gv) if isinstance(gv, float) else gv,
        ("%.2f" % cv) if isinstance(cv, float) else cv,
        rel(gv, cv)))
PYEOF
echo
echo "BENCH COMPLETE (gofips-only vs default-provider control; both NO_TICKET, TLS1.3, P-256, AES-256-GCM-SHA384)"
