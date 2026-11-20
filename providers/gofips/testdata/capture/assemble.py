"""assemble.py: write the evidence logs and records from a capture run.

Usage: assemble.py <work-dir> <repo-root> <out-dir>   (run.sh calls it)

Writes each log to <out-dir> with a short provenance header, masks host
paths, redacts the throwaway test key and shared secret printed by debug
traces, and writes the records whose content is captured values:
integrity, arm64, artifact digests, the OpenSSL version matrix and the
SSL_CTX_new reproduction. Fails if a host path or user name would reach
the output.
"""
import getpass
import pathlib
import re
import sys

W = pathlib.Path(sys.argv[1]).resolve()
# The evidence goes to an output directory (the release's evidence bundle),
# never into the repository.
T = pathlib.Path(sys.argv[3]).resolve()
T.mkdir(parents=True, exist_ok=True)
OUT, A64, PAR = W / "out", W / "out-arm64", W / "out-parity"
DATE = (OUT / "date.txt").read_text().strip()
SO = (OUT / "artifact.sha256").read_text().strip()
SHARED = str(W / "shared")
USER = getpass.getuser()

ENV = ("Linux x86_64, go1.26.11, OpenSSL 4.0.3 headers and libraries, "
       "CGO_ENABLED=1, GOFIPS140=v1.0.0, -buildvcs=false")
ENV_COMPAT = ENV.replace("OpenSSL 4.0.3 headers and libraries", "OpenSSL 4.0.3 headers")
BUILD = "GOWORK=off CGO_ENABLED=1 GOFIPS140=v1.0.0 go build -buildvcs=false -ldflags=-checklinkname=0 -buildmode=c-shared -o <dir>/gofips.so ."
REDACTED = "# Debug-trace values of the throwaway test key and shared secret are redacted."


def clean(text):
    text = text.replace(SHARED + "/tmp", "/tmp").replace(SHARED, "<work>")
    text = re.sub(r"^(gofips:.*)$",
                  lambda m: re.sub(r"\b(priv|secret)=[0-9a-f]{16,}", r"\1=<redacted>", m.group(1)),
                  text, flags=re.M)
    for leak in (str(W), USER + "/", "/home/"):
        assert leak not in text, f"host path leak: {leak}"
    return text


def body(path):
    return clean(path.read_text()).rstrip("\n") + "\n"


def strip_rc(text):
    return re.sub(r"\nrc=0\n?$", "\n", text)


def header(title, *lines, env=ENV, so=True):
    h = [f"# {title}", f"# Captured {DATE} from this repository's tree at the commit in RELEASE.txt.",
         f"# Environment: {env}."]
    h += [f"# {l}" for l in lines]
    if so:
        h.append(f"# Provider sha256 (environment-specific): {SO}")
    return "\n".join(h) + "\n"


# Refuse to write anything unless every capture reports a pass.
VERDICTS = {
    OUT / "guardtest-run.body": "GUARDTEST: ALL PASS", OUT / "regtest-run.body": "REGTEST: ALL PASS",
    OUT / "guardcheck-classification.body": "GUARDCHECK SELFTEST: ALL PASS",
    OUT / "tls-tcp-handshake-host.body": "TLS TCP HANDSHAKE: PASS",
    OUT / "node-integration-full-run.body": "NODE INTEGRATION: ALL STAGES PASSED",
    OUT / "interop-regression.body": "INTEROP REGRESSIONS: ALL PASS", OUT / "bench.all": "BENCH COMPLETE",
    OUT / "drbg-fips-mode.body": "fips140.Enabled: true", OUT / "drbg-nonfips-contrast.body": "fips140.Enabled: false",
    A64 / "acceptance-arm64-qemu.body": "ALL CHECKS PASSED", A64 / "tls-surface-arm64-qemu.body": "ALL CHECKS PASSED",
    A64 / "paramshape13-arm64.body": "PARAMSHAPE13: ALL PASS",
}
bad = [f"{p.name}: no '{v}'" for p, v in VERDICTS.items() if not p.exists() or v not in p.read_text()]
if (OUT / "tls13-gcm-run.body").read_text().count("TLS13 HANDSHAKE: ALL PASS") != 2:
    bad.append("tls13-gcm-run.body: not both handshake runs passed")
_gcm = (OUT / "tls13-gcm-run.body").read_text()
if re.search(r"^(FAIL|--- FAIL)", _gcm, re.M) or len(re.findall(r"^--- PASS", _gcm, re.M)) < 6:
    bad.append("tls13-gcm-run.body: the Go unit tests did not all run and pass in both modes")
if (OUT / "sha3-pbkdf2-run.body").read_text().count("SHA3PBKDF2: ALL PASS") != 2:
    bad.append("sha3-pbkdf2-run.body: not both modes passed")
if (OUT / "rsa-p384-run.body").read_text().count("RSAP384: ALL PASS") != 2:
    bad.append("rsa-p384-run.body: not both modes passed")
if (OUT / "tls12-run.body").read_text().count("TLS12: ALL PASS") != 2:
    bad.append("tls12-run.body: not both modes passed")
if re.search(r"DEFECT|REGRESSION", (OUT / "differential-run.body").read_text()):
    bad.append("differential-run.body: defects")
if (PAR / "fips-parity-run.body").read_text().count("ALL CHECKS PASSED") != 3:
    bad.append("fips-parity-run.body: not all three runs passed")
if (PAR / "paramshape13-x86.body").read_text().count("PARAMSHAPE13: ALL PASS") != 2:
    bad.append("paramshape13-x86.body: not both ABIs passed")
_mm = (OUT / "mode-matrix-run.body").read_text()
_mm_want = [f"fips godebug='{g}' -> LOAD: gofips provider {r}" for g, r in
            (("unset", "loaded"), ("off", "failed to load"), ("on", "loaded"), ("only", "loaded"))]
_mm_want += [f"nofips godebug='{g}' -> LOAD: gofips provider failed to load" for g in ("unset", "off", "on", "only")]
_mm_want += ["release build GOFIPS_DEBUG=1 trace lines: 0 (expect 0)"]
if any(l not in _mm.splitlines() for l in _mm_want) or "RELEASE-SCAN FAIL" in _mm \
        or not re.search(r"^debug build GOFIPS_DEBUG=1 trace lines: [1-9][0-9]* \(expect > 0\)$", _mm, re.M):
    bad.append("mode-matrix-run.body: the build/mode matrix or the release trace scan is not as expected")
_dflt = (OUT / "acceptance-default-build.body").read_text()
if "FAIL: gofips provider loads via OSSL_PROVIDER_load" not in _dflt \
        or "PASS: positive control: SHA2-256 fetchable from default provider" not in _dflt:
    bad.append("acceptance-default-build.body: the non-FIPS build was not refused at load")
_det = [l.split()[0] for l in (A64 / "determinism.txt").read_text().split("\n") if l.strip()] if (A64 / "determinism.txt").exists() else []
if len(_det) != 6 or len(set(_det[0::2])) != 1 or len(set(_det[1::2])) != 1:
    bad.append("determinism.txt: the arm64 runs are not three identical pairs")
_ecb = (A64 / "ecboundary.txt").read_text().splitlines() if (A64 / "ecboundary.txt").exists() else []
if _ecb != ["ECBOUNDARY: ALL PASS"] * 3:
    bad.append("ecboundary.txt: not three passing arm64 runs")
if not re.search(r"^rc=0$", (OUT / "bench.all").read_text(), re.M):
    bad.append("bench.all: the benchmark exited non-zero")
for _f, _rc in ((OUT / "node-integration-full-run.body", "rc=0"), (OUT / "interop-regression.body", "rc=0")):
    if not _f.read_text().rstrip().endswith(_rc):
        bad.append(f"{_f.name}: the runner exited non-zero")
# Every matrix file has one summary line per suite, each a pass: a suite
# that ran nothing prints an empty or zero result. The header names the
# OpenSSL the suites ran against, which must be the file's label.
MATRIX_ROWS = ["GOFIPS140 marker", "go test fips140=on", "go test fips140=only",
               "tls13_handshake fips140=on", "tls13_handshake fips140=only", "C acceptance",
               "differential T1-T13", "regtest", "guardtest", "audreg", "ecboundary", "paramshape13",
               "sha3_pbkdf2", "rsa_p384 fips140=on", "rsa_p384 fips140=only", "tls12 fips140=on",
               "tls12 fips140=only", "s_client -groups P-256", "config preference"]
MATRIX_OK = re.compile(r"ALL PASS|ALL CHECKS PASSED|^0 defects$|^TLS 1\.3 handshake completed|"
                       r"^[1-9][0-9]* pass, 0 fail$|^GOFIPS140=v1\.0\.0-c2097c7c$")
MATRIX_VERSIONS = ("3.0.13", "3.5.7", "3.6.5", "4.0.3")
# OpenSSL 3 and 4 in one process (E-44) runs only where both are installed.
DUAL_VERSION = "3.6.5"
for v in MATRIX_VERSIONS:
    m = W / f"matrix-{v}.txt"
    t = m.read_text() if m.exists() else ""
    if not t.startswith(f"openssl {v},"):
        bad.append(f"{m.name}: ran against {t.splitlines()[0] if t else 'nothing'}, not OpenSSL {v}")
    if re.search(r"FAIL|MISSING|failed [1-9]|compile FAILED|BUILD FAILED", t):
        bad.append(f"{m.name}: failures")
    rows = dict(re.findall(r"^  (\S.*?)[ \t]{2,}(.*)$", t, re.M))
    for label in MATRIX_ROWS:
        value = rows.get(label, "").strip()
        if not MATRIX_OK.search(value):
            bad.append(f"{m.name}: {label}: {value or 'no result'}")
    dual = rows.get("dual OpenSSL 3+4", "").strip()
    if (dual != "DUALOPENSSL: ALL PASS") if v == DUAL_VERSION else not dual.startswith("SKIP: "):
        bad.append(f"{m.name}: dual OpenSSL 3+4: {dual or 'no result'}")
if bad:
    sys.exit("capture failed, nothing written:\n  " + "\n  ".join(bad))


def write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    print("wrote", path.relative_to(T))


def section(text, start):
    lines = text.splitlines()
    i = next(n for n, l in enumerate(lines) if l.startswith("=== " + start))
    j = next((n for n in range(i + 1, len(lines))
              if lines[n].startswith("=== ") or lines[n].startswith("NODE INTEGRATION")), len(lines))
    return "\n".join(l for l in lines[i + 1:j] if l.strip()) + "\n"


# ---- host suites ----
write(T / "differential-run.log", header("differential_repro.c T1-T13 run (E-30).", f"Build: {BUILD}",
      "Run: for t in 1..13: GODEBUG=fips140=on differential_repro <dir> $t") + body(OUT / "differential-run.body"))
write(T / "guardtest-run.log", header("guardtest.c run (E-31).", f"Build: {BUILD}",
      "Run: GODEBUG=fips140=on guardtest <dir>") + body(OUT / "guardtest-run.body"))
write(T / "regtest-run.log", header("regtest.c run.", f"Build: {BUILD}",
      "Run: GODEBUG=fips140=on regtest (loads gofips from /tmp/modematrix)") + body(OUT / "regtest-run.body"))
write(T / "sha3-pbkdf2-run.log", header("SHA-3, SHAKE, HMAC-SHA3, HKDF-SHA3, PBKDF2 and streaming ECDSA (E-39): sha3_pbkdf2.c under fips140=on and only.",
      f"Build: {BUILD}", "Reference: the default provider in a separate library context.") + body(OUT / "sha3-pbkdf2-run.body"))
write(T / "rsa-p384-run.log", header("RSA verification, P-384, certificate chains and TLS 1.3 (E-40): rsa_p384.c under fips140=on and only.",
      f"Build: {BUILD}", "Keys, certificates and peers from the default provider in a separate library context.") + body(OUT / "rsa-p384-run.body"))
write(T / "tls12-run.log", header("TLS 1.2 (E-42): tls12.c under fips140=on and only: TLS1-PRF against the default provider, TLS 1.2 handshakes with GCM records and resumption, refusals.",
      f"Build: {BUILD}", "Keys, certificates and peers from the default provider in a separate library context.") + body(OUT / "tls12-run.body"))
write(T / "tls13-gcm-run.log", header("TLS 1.3 GCM (E-37): gcm_tls13_test.go and tls13_handshake.c under fips140=on and only.",
      f"Build: {BUILD}", "Go test timings removed.") + body(OUT / "tls13-gcm-run.body"))
write(T / "mode-matrix-run.log", header("Build/mode matrix and release-binary trace scan (E-33).",
      "Run: bash testdata/mode-matrix.sh (builds its own release and debug artifacts).", so=False)
      + body(OUT / "mode-matrix-run.body"))
write(T / "acceptance-default-build.log", header(
    "provider_acceptance.c against a build without GOFIPS140 (E-02).",
    "Build: CGO_ENABLED=1 go build -buildvcs=false -ldflags=-checklinkname=0 -buildmode=c-shared -o /tmp/temperfips-default.so .",
    "Run: GOFIPS_SO=/tmp/temperfips-default.so provider_acceptance",
    "The exclusive-FIPS gate refuses the unstamped build at provider init, so the load check",
    "fails; the default-provider positive controls run first and pass.", so=False)
      + body(OUT / "acceptance-default-build.body"))
write(T / "guardcheck-classification.log", header("guardcheck.sh classifier evidence; temp path shown as <tmp>.", so=False)
      + "\n" + body(OUT / "guardcheck-classification.body"))
FM = "Build: GOFIPS140=v1.0.0 go build -o fipsmode ./testdata/fipsmode"
write(T / "drbg-fips-mode.log", header("FIPS mode on (E-09).", FM, "Run: GODEBUG=fips140=on fipsmode", so=False)
      + body(OUT / "drbg-fips-mode.body"))
write(T / "drbg-nonfips-contrast.log", header("FIPS mode off, same binary (E-09).", FM, "Run: GODEBUG=fips140=off fipsmode", so=False)
      + body(OUT / "drbg-nonfips-contrast.body"))
write(T / "tls-tcp-handshake-host.log", header("tls_tcp_handshake.c: TLS 1.3 over loopback TCP, gofips on both ends (E-22).",
      f"Build: {BUILD}", "Run: GODEBUG=fips140=on tls_tcp_handshake <dir>",
      "Client and server run on separate threads; their lines can interleave.") + body(OUT / "tls-tcp-handshake-host.body"))

# ---- Node integration and its host suites ----
node = strip_rc(body(OUT / "node-integration-full-run.body"))
node_digests = dict((name, sha) for sha, name in re.findall(r"^([0-9a-f]{64})\s+\S*/(temperfips(?:-poison)?\.so)$", node, re.M))
write(T / "node-integration-full-run.log", header(
    "run-node-integration.sh (E-13, E-14).", REDACTED[2:],
    "Run: GOFIPS_LIBCRYPTO_DIR=<compat pair> run-node-integration.sh node:local-amd64",
    "Image: node built from images/node/apko.lock.json (versions in the run header).",
    "Host C suites link the OpenSSL 3.5.9 compat pair (fetch-compat-openssl3.sh).", env=ENV_COMPAT, so=False) + node)
write(T / "tls-surface-amd64.log", header(
    "tls_surface_test.c, amd64 (E-03): the TLS-surface stage of node-integration-full-run.log.", REDACTED[2:],
    "Linked against the OpenSSL 3.5.9 compat pair; gofips-only OPENSSL_CONF; GODEBUG=fips140=on.",
    env=ENV_COMPAT, so=False) + section(node, "TLS-surface suite"))
write(T / "acceptance-fips-build.log", header(
    "provider_acceptance.c, amd64 (E-01): the C acceptance stage of node-integration-full-run.log.",
    "Linked against the OpenSSL 3.5.9 compat pair; gofips-only OPENSSL_CONF; GODEBUG=fips140=on.",
    env=ENV_COMPAT, so=False) + section(node, "C acceptance suite"))
write(T / "node-integration/interop-regression.log", header(
    "run-interop-regression.sh (E-19).", "Run: run-interop-regression.sh node:local-amd64", so=False)
      + strip_rc(body(OUT / "interop-regression.body")))

# ---- benchmark ----
bench = body(OUT / "bench.all")


def bench_part(label):
    lines = bench.splitlines()
    i = lines.index(f"--- {label} ---")
    out = []
    for l in lines[i + 1:]:
        if l.startswith("---") or l.startswith("==="):
            break
        if l.startswith("round ") or l.startswith("BENCH-JSON"):
            out.append(l)
    return "\n".join(out) + "\n"


BH = ("run-tls-bench.sh: node-tls-bench.js in the node image, 3 rounds, TLS 1.3, ECDSA P-256, "
      "AES-256-GCM-SHA384, SSL_OP_NO_TICKET. Native amd64.")
write(T / "node-integration/bench-gofips-amd64.log", header("TLS benchmark, gofips-only config (E-25).", BH, so=False)
      + bench_part("gofips-only"))
write(T / "node-integration/bench-control-amd64.log", header("TLS benchmark, default-provider control (E-25).", BH, so=False)
      + bench_part("default-provider control"))

# ---- arm64 ----
art = (A64 / "artifact.txt").read_text()
A64_SO = re.search(r"([0-9a-f]{64})\s+/tmp/a64/gofips.so", art).group(1)
A64_CRYPTO = re.search(r"([0-9a-f]{64})\s+\S*libcrypto.so.3", art).group(1)
a64env = (A64 / "env.txt").read_text()
QEMU = re.search(r"qemu-aarch64 version (\S+) \(([^)]+)\)", a64env)
LIBSSL = re.search(r"libssl3t64:arm64 (\S+)", a64env).group(1)
OSSL_A64 = LIBSSL.split("-")[0]
A64ENV = (f"Cross-build: GOARCH=arm64 CC=aarch64-linux-gnu-gcc CGO_ENABLED=1 GOFIPS140=v1.0.0, Debian arm64 "
          f"OpenSSL {OSSL_A64} headers; run under qemu-aarch64 {QEMU.group(1)} user-mode emulation.")
for rel, title, src in [("acceptance-arm64-qemu.log", "provider_acceptance.c, arm64 under qemu (E-12).", "acceptance-arm64-qemu.body"),
                        ("tls-surface-arm64-qemu.log", "tls_surface_test.c, arm64 under qemu, gofips-only OPENSSL_CONF (E-04).",
                         "tls-surface-arm64-qemu.body")]:
    write(T / rel, f"# {title}\n# Captured {DATE} from this repository's tree.\n# {A64ENV}\n"
          f"# Provider sha256 (environment-specific): {A64_SO}\n" + body(A64 / src))
ecb = (A64 / "ecboundary.txt").read_text().splitlines()
det = sorted(set((A64 / "determinism.txt").read_text().split()))
det_ok = len([d for d in det if len(d) == 64]) == 2
write(T / "arm64-evidence.txt", f"""arm64 (aarch64) build and run evidence (E-12)
Captured {DATE} from this repository's tree.

Cross-build (golang:1.26.11 container, Debian arm64 OpenSSL {OSSL_A64} headers
from the libssl-dev:arm64 multiarch package):
  GOARCH=arm64 CC=aarch64-linux-gnu-gcc CGO_ENABLED=1 GOFIPS140=v1.0.0 \\
  CGO_CFLAGS="-I/usr/include -I/usr/include/aarch64-linux-gnu" \\
  go build -buildvcs=false -ldflags=-checklinkname=0 -buildmode=c-shared -o gofips.so .

Artifact: {art.splitlines()[0].split(',')[0]}, ARM aarch64, dynamically linked
go version -m: build GOARCH=arm64, build GOFIPS140=v1.0.0-c2097c7c
DT_NEEDED: libc.so.6 only; nm -D --undefined-only shows {re.search(r'symbols: (\d+)', art).group(1)}
libcrypto-namespaced symbols
sha256: {A64_SO}
(environment-specific)

Execution: qemu-aarch64 {QEMU.group(1)} user-mode emulation ({QEMU.group(2)}) with
Debian's arm64 glibc and OpenSSL {OSSL_A64} (libssl3t64:arm64 {LIBSSL},
libcrypto.so.3 sha256 {A64_CRYPTO}).
The C suites were cross-compiled against the same arm64 OpenSSL headers.

Results:
- provider_acceptance.c: {(A64 / 'acceptance-arm64-qemu.body').read_text().strip().splitlines()[-1]}. Log: acceptance-arm64-qemu.log
- tls_surface_test.c under the gofips-only OPENSSL_CONF:
  {(A64 / 'tls-surface-arm64-qemu.body').read_text().strip().splitlines()[-1]}. Log: tls-surface-arm64-qemu.log (E-04)
- ecboundary.c: {ecb[0] if len(set(ecb)) == 1 else 'MIXED RESULTS'}, {len(ecb)} of {len(ecb)} runs
- paramshape13.c: see ABI 3 in paramshape13-3abi.log
- Determinism: three runs of each suite gave {'byte-identical output' if det_ok else 'DIFFERING output'}.

Scope: functional evidence under emulation only. No native arm64
execution and no arm64 performance figures.
""")

# ---- official FIPS provider parity, three-ABI parameter shapes ----
fsha = (PAR / "fips.sha256").read_text().strip()
fpkg = (W / "fips" / "fips.package").read_text().strip()
psha = (PAR / "artifact.sha256").read_text().strip()
write(T / "fips-parity-run.log",
      f"# fips-parity-probe.c run (E-36).\n# Captured {DATE} from this repository's tree.\n# Environment: {ENV}.\n"
      f"# Genuine fips.so: {fpkg} (Rocky Linux 10; RPM signature verified), sha256 {fsha}.\n"
      f"# Control: the same probe built with -DPARITY_PROVIDER='\"default\"'.\n"
      f"# Provider sha256 (environment-specific): {psha}\n\n" + body(PAR / "fips-parity-run.body"))
write(T / "paramshape13-3abi.log",
      f"# paramshape13.c on three ABIs.\n# Captured {DATE} from this repository's tree.\n"
      f"# ABI 1 and 2: {ENV}. ABI 3: {A64ENV}\n\n"
      + body(PAR / "paramshape13-x86.body")
      + f"\n== ABI 3: arm64 (aarch64) under qemu-user, Debian arm64 OpenSSL {OSSL_A64}\n"
      + body(A64 / "paramshape13-arm64.body"))

# ---- integrity record (E-08) ----
zsha = (OUT / "zip.sha256").read_text().strip()
SP_DIGEST = "daf3614e0406f67ae6323c902db3f953a1effb199142362a039e7526dfb9368b"
fon = (OUT / "drbg-fips-mode.body").read_text()
foff = (OUT / "drbg-nonfips-contrast.body").read_text()
abc = lambda t: re.search(r"sha256\(abc\): ([0-9a-f]{8})", t).group(1)
write(T / "integrity-evidence.txt", f"""Go Cryptographic Module integrity and approved-mode evidence (E-08)
Captured {DATE} from this repository's tree.

Toolchain: go1.26.11 linux/amd64
Validated archive: $GOROOT/lib/fips140/v1.0.0-c2097c7c.zip
Archive sha256: {zsha}
SP 5247 section 11.1 digest: {SP_DIGEST}
Match: {'yes' if zsha == SP_DIGEST else 'NO'}. CI checks this on every run (gofips-suites.yml, "FIPS module
integrity").

FIPS build (SP 5247 section 11.1, unmodified frozen source):
  GOFIPS140=v1.0.0 go build -ldflags=-checklinkname=0 -buildmode=c-shared -o libtemperfips.so .

go version -m on the provider:
{(OUT / 'so-markers.txt').read_text().rstrip()}

Runtime mode (testdata/fipsmode, built with GOFIPS140=v1.0.0):
  GODEBUG=fips140=on:  {fon.splitlines()[0]},  sha256(abc) = {abc(fon)}...
  GODEBUG=fips140=off: {foff.splitlines()[0]}, sha256(abc) = {abc(foff)}...
  In FIPS mode the module's integrity check and self-tests run at init and
  a failure aborts the process; the process completing with
  fips140.Enabled true is the observable result. Logs: drbg-fips-mode.log,
  drbg-nonfips-contrast.log (E-09).
""")

# ---- artifact digests (E-21) ----
rows = [
    (SO, "gofips.so", "differential, guardtest, regtest, TLS 1.3 GCM, TCP handshake (E-30, E-31, E-37, E-22)"),
    (node_digests["temperfips.so"], "temperfips.so", "node integration, TLS surface, C acceptance (E-14, E-03, E-01)"),
    (node_digests["temperfips-poison.so"], "temperfips-poison.so", "poison control (E-14)"),
    (psha, "gofips.so", "official FIPS provider parity, paramshape13 ABI 1-2 (E-36)"),
    (A64_SO, "gofips.so (arm64)", "arm64 suites (E-12, E-04)"),
]
write(T / "artifact-digests.txt", "".join(f"{s}  {n}: {u}\n" for s, n, u in rows))
# ---- SSL_CTX_new reproduction (E-27) ----
ctx = (OUT / "ctxtest.body").read_text()
good = [l for l in ctx.split("== invalid")[0].splitlines() if "SSL_CTX_new" in l]
bad = [re.sub(r"^[0-9A-F]+:", "", l) for l in ctx.split("== invalid")[1].splitlines() if "SSL_CTX_new" in l]
write(T / "ctx-mechanism-run.txt", f"""SSL_CTX_new with a valid and an invalid provider module path (E-27).
Captured {DATE}, go1.26.11, OpenSSL 4.0.3, release build.

1. Valid module path:
   $ cc ctxtest.c -o ctxtest $(pkg-config --cflags --libs libssl libcrypto)
   $ OPENSSL_CONF=<gofips-only conf, module = built temperfips.so> ./ctxtest
""" + "".join(f"   {l}\n" for l in good) + """
2. Invalid module path (the container-only /gofips path, used on a host):
   $ OPENSSL_CONF=<same conf, module = /gofips/temperfips.so> ./ctxtest
""" + "".join(f"   {l}\n" for l in bad))

# ---- OpenSSL version matrix (E-38) ----
mats = {v: (W / f"matrix-{v}.txt").read_text() for v in MATRIX_VERSIONS}


def cell(text, key):
    m = re.search(r"^  " + re.escape(key) + r"\s+(.*)$", text, re.M)
    v = m.group(1).strip() if m else "MISSING"
    v = (v.replace("TLS13 HANDSHAKE: ", "").replace("REGTEST: ", "").replace("GUARDTEST: ", "")
         .replace("AUDREG: ", "").replace("ECBOUNDARY: ", "").replace("SHA3PBKDF2: ", "").replace("RSAP384: ", "").replace("TLS12: ", "").replace("ALL CHECKS PASSED", "ALL PASS"))
    v = re.sub(r"PARAMSHAPE13: ALL PASS.*", "ALL PASS", v)
    v = re.sub(r"TLS 1.3 handshake completed.*", "completed", v)
    v = re.sub(r"(\d+) pass, 0 fail", r"\1 pass", v)
    v = re.sub(r"ALL PASS \((\d+) skipped\)", "ALL PASS (1)", v)
    v = re.sub(r"ALL PASS \(\d+ checks\)", "ALL PASS", v)
    v = re.sub(r"ALL PASS \(\d+ checks, chains and TLS skipped\)", "ALL PASS (3)", v)
    v = re.sub(r"^DUALOPENSSL: ALL PASS$", "ALL PASS", v)
    v = re.sub(r"^CONFIGPREF: ALL PASS$", "ALL PASS", v)
    v = re.sub(r"^SKIP: .*", "n/a (4)", v)
    return v


ROWS = [("go test fips140=on (E-37)", "go test fips140=on"), ("go test fips140=only (E-37)", "go test fips140=only"),
        ("tls13_handshake on (E-37)", "tls13_handshake fips140=on"), ("tls13_handshake only (E-37)", "tls13_handshake fips140=only"),
        ("C acceptance (E-01)", "C acceptance"), ("differential T1-T13 (E-30)", "differential T1-T13"),
        ("regtest", "regtest"), ("guardtest (E-31)", "guardtest"), ("audreg", "audreg"),
        ("ecboundary (E-34)", "ecboundary"), ("paramshape13", "paramshape13"), ("sha3_pbkdf2 (E-39)", "sha3_pbkdf2"),
        ("rsa_p384 on (E-40)", "rsa_p384 fips140=on"), ("rsa_p384 only (E-40)", "rsa_p384 fips140=only"),
        ("tls12 on (E-42)", "tls12 fips140=on"), ("tls12 only (E-42)", "tls12 fips140=only"), ("s_client -groups P-256 (2)", "s_client -groups P-256"),
        ("config preference (E-45)", "config preference"), ("dual OpenSSL 3+4 (E-44)", "dual OpenSSL 3+4")]
table = "".join(f"  {label:<30}" + "".join(f"{cell(mats[v], key):<15}" for v in mats).rstrip() + "\n" for label, key in ROWS)
first_use = {v: re.search(r"first-use: .*\((\d+/\d+) rounds failed\)", mats[v]).group(1) for v in mats}
write(T / "openssl-versions-check.txt", f"""Provider by OpenSSL version (E-38)
Captured {DATE} from this repository's tree.
Toolchain: go1.26.11 (golang:1.26.11, ubuntu:24.04 and wolfi-base containers)
OpenSSL: 3.0.13 (Ubuntu 24.04), 3.5.7 (Debian), 3.6.5 (Wolfi, the
libcrypto.so.3 the node images ship), 4.0.3 (built from the verified
release tarball)

Results                         3.0.13         3.5.7          3.6.5          4.0.3
  GOFIPS140 marker              v1.0.0-c2097c7c (all)
{table}
  (1) Two checks skipped by design below OpenSSL 3.5: rand-hook needs
      RAND_set1_random_provider, and the empty-salt parity check has no
      reference behavior (page 09).
  (2) openssl s_client loaded with gofips and base only, against an
      openssl s_server using the default provider: a TLS 1.3 handshake
      with gofips as the client and the group named "P-256".
  (3) Chain and TLS cases skipped: under fips140=only Go refuses SHA-1,
      so libcrypto has no certificate fingerprints, and OpenSSL 3.0.13
      builds no certificate chain without them (3.5.7, 3.6.5 and 4.0.3 do).
  (4) Needs libcrypto.so.3 and libcrypto.so.4 in one process, as in the
      node images; only the Wolfi container has both. OpenSSL 3.6.5 and
      4.0.3 each load the same gofips.so, built against the OpenSSL 4.0.3
      headers, with the config the images ship: known answers, MD5
      unusable, every digest served by gofips, PEM keys loaded, and 4
      threads per library interleaved.

audreg cases these results depend on:
  point-fmt   EC keys report point-format "uncompressed"; OpenSSL 3.x
              libssl rejects an EC peer key that reports none.
  names       every digest, cipher and keymgmt algorithm registers all
              the names the default provider registers for it.
  first-use   concurrent first TLS contexts in 20 fresh library contexts
              all have TLS 1.3 ciphers (rounds failed: {', '.join(f'{v} {first_use[v]}' for v in mats)}).
  TLS caps    the TLS-GROUP capability exposes secp256r1 and its alias
              P-256; a gofips-only TLS context accepts both names.
""")

# ---- consistency checks ----
inv = (OUT / "panictest-inventory.check").read_text()
assert "matches the current dispatch surface" in inv, "panictest-inventory.txt is stale: " + inv
print("done; panictest-inventory.txt matches the current dispatch surface")
