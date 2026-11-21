#!/usr/bin/env python3
"""Smoke test for the python-fips image. Runs inside the container; any
failed assert exits non-zero.

Checks that hashlib, hmac (including hmac.new) and ssl are served by gofips (the Go Cryptographic
Module), that non-approved algorithms are refused, and that neither the
default nor the legacy OpenSSL provider is loaded.
"""
import hashlib
import hmac
import os
import re
import ssl

assert os.environ.get("OPENSSL_CONF") == "/etc/ssl/openssl-gofips.cnf"
assert os.environ.get("GODEBUG") == "fips140=on"

ABC_SHA256 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
ABC_SHA3_256 = "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
PBKDF2_SHA256 = "8514638175a45bc45eb1f22f04ff7d27f4f8be480498c455ff4b494ce8d1e7d2"  # host OpenSSL default provider
assert hashlib.sha256(b"abc").hexdigest() == ABC_SHA256
assert hashlib.sha3_256(b"abc").hexdigest() == ABC_SHA3_256
assert hashlib.shake_256(b"abc").hexdigest(32) == "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739"
for name, want in (
        ("sha384", "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"),
        ("sha512", "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"),
        ("sha3_224", "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf"),
        ("sha3_384", "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25"),
        ("sha3_512", "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"),
        ("sha1", "a9993e364706816aba3e25717850c26c9cd0d89d")):
    assert hashlib.new(name, b"abc").hexdigest() == want, name
assert hashlib.shake_128(b"abc").hexdigest(16) == "5881092dd818bf5cf8a3ddb793fbcba7"
# hmac is the python-fips module (packages/python-fips-<line>/hmac.py): every
# HMAC goes through the provider, and _hashlib's legacy HMAC_CTX is replaced.
import _hashlib  # noqa: E402
assert (hmac.__doc__ or "").startswith("HMAC (RFC 2104) for the python-fips image"), "stdlib hmac in use"
assert _hashlib.hmac_new is not None and _hashlib.hmac_new.__module__ == "hmac", "_hashlib.hmac_new not replaced"
h = hmac.new(b"k" * 32, b"ab", "sha3_256")
h.update(b"c")
assert h.digest() == hmac.digest(b"k" * 32, b"abc", "sha3_256")
assert h.hexdigest()[:16] == "e444577fc23e76dc"
assert hashlib.pbkdf2_hmac("sha256", b"password", b"0123456789abcdef", 1000, 32).hex() == PBKDF2_SHA256


def refused(label, fn):
    try:
        fn()
    except ValueError:
        return
    raise AssertionError(f"{label} must be refused")


refused("md5", lambda: hashlib.md5(b"abc"))
refused("md4", lambda: hashlib.new("md4", b"abc"))
refused("ripemd160", lambda: hashlib.new("ripemd160", b"abc"))
refused("sha224", lambda: hashlib.sha224(b"abc"))
refused("sha512_256", lambda: hashlib.new("sha512_256", b"abc"))
refused("blake2b", lambda: hashlib.blake2b(b"abc"))
refused("blake2s", lambda: hashlib.blake2s(b"abc"))
# Python 3.14's built-in HMAC (_hmac) is removed: it would compute HMAC
# outside the module whenever OpenSSL refuses.
try:
    import _hmac  # noqa: F401
    raise AssertionError("_hmac imported in python-fips")
except ImportError:
    pass
refused("hmac.new with a key under 112 bits", lambda: hmac.new(b"short", b"abc", "sha256"))
refused("hmac.new with SHA-1", lambda: hmac.new(b"k" * 32, b"abc", "sha1"))
refused("hmac.new with MD5", lambda: hmac.new(b"k" * 32, b"abc", "md5"))
import functools  # noqa: E402
# A callable that returns a hashlib hash only names the digest; the provider computes.
assert hmac.new(b"k" * 32, b"abc", lambda d=b"": hashlib.sha256(d)).digest() == hmac.digest(b"k" * 32, b"abc", "sha256")
refused("hmac.new with a digestmod that is not a hashlib hash", lambda: hmac.new(b"k" * 32, b"abc", lambda d=b"": object()))
refused("hmac.new with functools.partial(hashlib.new, 'sha1')", lambda: hmac.new(b"k" * 32, b"abc", functools.partial(hashlib.new, "sha1")))
refused("_hashlib.hmac_new with a key under 112 bits", lambda: _hashlib.hmac_new(b"short", b"abc", "sha256"))
refused("hmac.digest with MD5", lambda: hmac.digest(b"k" * 32, b"abc", "md5"))
assert hmac.new(b"k" * 32, b"abc", hashlib.sha256).digest() == hmac.digest(b"k" * 32, b"abc", "sha256")
refused("pbkdf2 with an 8-byte salt", lambda: hashlib.pbkdf2_hmac("sha256", b"password", b"01234567", 1000, 32))
refused("pbkdf2 with SHA-1", lambda: hashlib.pbkdf2_hmac("sha1", b"password", b"0123456789abcdef", 1000, 32))
refused("pbkdf2 with a 104-bit derived key", lambda: hashlib.pbkdf2_hmac("sha256", b"password", b"0123456789abcdef", 1000, 13))

# A local TLS 1.3 server with default options (tickets on), then a resumed
# connection: the PSK binder is an HMAC signature in gofips.
import socket  # noqa: E402
import threading  # noqa: E402
import warnings  # noqa: E402

srv_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
srv_ctx.load_cert_chain("/tls/cert.pem", "/tls/key.pem")
cli_ctx = ssl.create_default_context(cafile="/tls/cert.pem")
listener = socket.create_server(("127.0.0.1", 0))
port = listener.getsockname()[1]


def serve(n):
    for _ in range(n):
        raw, _ = listener.accept()
        try:
            with srv_ctx.wrap_socket(raw, server_side=True) as c:
                c.sendall(b"hello")
        except ssl.SSLError:
            raw.close()


t = threading.Thread(target=serve, args=(2,), daemon=True)
t.start()


def connect(session=None):
    with socket.create_connection(("127.0.0.1", port), timeout=10) as raw:
        with cli_ctx.wrap_socket(raw, server_hostname="localhost", session=session) as c:
            assert c.recv(5) == b"hello" and c.version() == "TLSv1.3"
            return c.session, c.session_reused


sess, reused = connect()
assert not reused and sess is not None and sess.has_ticket, "no session ticket received"
_, reused = connect(sess)
assert reused, "TLS 1.3 session not resumed"
t.join(10)
tls12 = ssl.create_default_context(cafile="/tls/cert.pem")
tls12.maximum_version = ssl.TLSVersion.TLSv1_2
threading.Thread(target=serve, args=(2,), daemon=True).start()
with socket.create_connection(("127.0.0.1", port), timeout=10) as raw:
    with tls12.wrap_socket(raw, server_hostname="localhost") as c:
        assert c.recv(5) == b"hello" and c.version() == "TLSv1.2" and "GCM" in c.cipher()[0], c.cipher()
# Both ends offer a TLS 1.2 CBC suite, so the refusal comes from the
# provider, not from a missing shared suite.
tls12.set_ciphers("ECDHE-ECDSA-AES128-SHA256")
try:
    with socket.create_connection(("127.0.0.1", port), timeout=10) as raw:
        with tls12.wrap_socket(raw, server_hostname="localhost") as c:
            c.recv(5)
    raise AssertionError("a TLS 1.2 CBC suite must be refused")
except (ssl.SSLError, ConnectionError) as e:
    assert not re.search(r"no (shared )?cipher|NO_SHARED_CIPHER|NO_CIPHERS|HANDSHAKE_FAILURE", str(e), re.I), \
        f"a TLS 1.2 CBC suite must be refused by the provider: {e}"
# P-521 only, on both ends: no group the provider serves.
p521 = ssl.create_default_context(cafile="/tls/cert.pem")
p521.set_ecdh_curve("secp521r1")
srv_ctx.set_ecdh_curve("secp521r1")
# TLS 1.1 only, on the client. Wolfi's OpenSSL build has no TLS 1.1 (as in
# the plain python image).
tls11 = ssl.create_default_context(cafile="/tls/cert.pem")
with warnings.catch_warnings():
    warnings.simplefilter("ignore", DeprecationWarning)
    tls11.minimum_version = tls11.maximum_version = ssl.TLSVersion.TLSv1_1
threading.Thread(target=serve, args=(2,), daemon=True).start()
for label, ctx in (("a P-521 key exchange", p521), ("TLS 1.1", tls11)):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=10) as raw:
            with ctx.wrap_socket(raw, server_hostname="localhost") as c:
                c.recv(5)
        raise AssertionError(f"{label} must fail")
    except (ssl.SSLError, ConnectionError):
        pass
listener.close()
try:
    ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER).load_cert_chain("/tls/rsa-cert.pem", "/tls/rsa-key.pem")
    raise AssertionError("an RSA private key must be refused")
except ssl.SSLError:
    pass

# A public endpoint with an RSA certificate and an RSA chain, verified.
tls = "SKIPPED (SMOKE_NO_NETWORK=1)"
if os.environ.get("SMOKE_NO_NETWORK") != "1":
    host = "packages.wolfi.dev"
    with socket.create_connection((host, 443), timeout=10) as raw:
        with ssl.create_default_context().wrap_socket(raw, server_hostname=host) as conn:
            assert conn.version() == "TLSv1.3", conn.version()
            tls = f"TLS 1.3 to {host}, chain verified"
    npm = ssl.create_default_context()
    npm.maximum_version = ssl.TLSVersion.TLSv1_2
    with socket.create_connection(("registry.npmjs.org", 443), timeout=10) as raw:
        with npm.wrap_socket(raw, server_hostname="registry.npmjs.org") as conn:
            assert conn.version() == "TLSv1.2", conn.version()
            tls += ", TLS 1.2 to registry.npmjs.org, chain verified"

# It holds in a virtualenv, with an application sitecustomize on PYTHONPATH,
# and without site initialisation (-S).
import subprocess  # noqa: E402
import tempfile  # noqa: E402
import sys  # noqa: E402
import venv  # noqa: E402
with tempfile.TemporaryDirectory() as d:
    venv.create(d, with_pip=False)
    probe = ("import hmac, functools, hashlib\n"
             "for f in (lambda: hmac.new(b'short', b'm', 'sha256'),\n"
             "          lambda: hmac.new(b'k' * 32, b'm', functools.partial(hashlib.new, 'sha1'))):\n"
             "    try:\n"
             "        f(); raise SystemExit('HMAC not refused')\n"
             "    except ValueError:\n"
             "        pass\n")
    os.makedirs(d + "/app")
    open(d + "/app/sitecustomize.py", "w").close()
    for label, argv, env in [("virtualenv", [d + "/bin/python", "-c", probe], None),
                             ("PYTHONPATH sitecustomize", [sys.executable, "-c", probe], {**os.environ, "PYTHONPATH": d + "/app"}),
                             ("python -S", [sys.executable, "-S", "-c", probe], None)]:
        r = subprocess.run(argv, capture_output=True, text=True, env=env)
        assert r.returncode == 0, label + ": " + r.stdout + r.stderr
    # _hashlib's own hmac_new, before anything imports hmac.
    r = subprocess.run([sys.executable, "-c", "import _hashlib\n"
                        "try:\n    _hashlib.hmac_new(b'k', b'm', 'sha256')\nexcept ValueError:\n    raise SystemExit(0)\n"
                        "raise SystemExit('not refused')"], capture_output=True, text=True)
    assert r.returncode == 0, "_hashlib.hmac_new short key: " + r.stdout + r.stderr

maps = open("/proc/self/maps").read()
assert "gofips.so" in maps, "gofips provider not loaded"
assert "legacy.so" not in maps, "legacy provider loaded"

# Without OPENSSL_CONF, the default openssl.cnf is the gofips-only config:
# the child computes SHA-256 in gofips and OpenSSL refuses MD5.
r = subprocess.run([sys.executable, "-c",
                    "import hashlib\n"
                    f"assert hashlib.sha256(b'abc').hexdigest() == {ABC_SHA256!r}\n"
                    "assert 'gofips.so' in open('/proc/self/maps').read()\n"
                    "try:\n    hashlib.md5()\nexcept ValueError as e:\n    print(e)\n    raise SystemExit(0)\n"
                    "raise SystemExit('md5 computed')"], env={}, capture_output=True, text=True)
assert r.returncode == 0 and "unsupported" in r.stdout, "child started without OPENSSL_CONF: " + r.stdout + r.stderr

# multiprocessing defaults to forkserver on every line (Python 3.14 does;
# 3.13 through packages/python-fips-3.13/sitecustomize.py): a fork()ed child
# can hang in the provider's Go runtime.
r = subprocess.run([sys.executable, "-c", "import multiprocessing as m; print(m.get_start_method())"],
                   capture_output=True, text=True)
assert r.stdout.strip() == "forkserver", "multiprocessing start method: " + r.stdout + r.stderr

print(f"smoke ok: python-fips {sys.version.split()[0]} (gofips serves hashlib/hmac/ssl; local TLS 1.3 server with tickets and resumption, local TLS 1.2 (GCM; CBC refused); {tls}; md5, sha224, blake2, short-salt pbkdf2, P-521, RSA private keys refused; no TLS 1.1 in the base; no legacy; multiprocessing forkserver)")
