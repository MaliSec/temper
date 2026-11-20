#!/usr/bin/env python3
"""Smoke test for the Temper python image. Runs inside the container as the
image's user; any failed assert exits non-zero.

Checks the Python interpreter of the line under test, stdlib modules backed by native libraries,
a TLS handshake using the image's CA bundle (skipped with SMOKE_NO_NETWORK=1),
the nonroot uid, and the absence of a shell, apk and pip.
"""
import os
import shutil
import ssl
import sys

NONROOT_UID = 65532
# The line under test, from the runner (PYTHON_LINE=3.13); the interpreter
# itself is chosen by the image's entrypoint path.
EXPECTED_MAJOR_MINOR = tuple(int(x) for x in os.environ.get("PYTHON_LINE", "3.14").split("."))

assert sys.version_info[:2] == EXPECTED_MAJOR_MINOR, (
    f"unexpected python line: {sys.version}")

import bz2  # noqa: E402  (libbz2)
import ctypes  # noqa: E402  (libffi)
import hashlib  # noqa: E402  (libcrypto via _hashlib)
import lzma  # noqa: E402  (xz)
import sqlite3  # noqa: E402  (sqlite-libs)
import ssl  # noqa: E402  (openssl)
import zlib  # noqa: E402  (zlib)

assert hashlib.sha256(b"temper").hexdigest()  # libcrypto path
assert sqlite3.connect(":memory:").execute("select 1").fetchone() == (1,)
assert zlib.decompress(zlib.compress(b"x")) == b"x"
assert bz2.decompress(bz2.compress(b"x")) == b"x"
assert lzma.decompress(lzma.compress(b"x")) == b"x"
assert ctypes.CDLL("libcrypto.so.4")  # openssl lib loads via ctypes

tls_ok = False
if os.environ.get("SMOKE_NO_NETWORK") != "1":
    host = "packages.wolfi.dev"
    ctx = ssl.create_default_context()
    import socket  # noqa: E402
    with socket.create_connection((host, 443), timeout=10) as raw:
        with ctx.wrap_socket(raw, server_hostname=host) as tls:
            assert tls.version() is not None
            tls_ok = True
    print(f"TLS: verified against {host} ({ssl.OPENSSL_VERSION.split()[0]})")
else:
    print("TLS: SKIPPED (SMOKE_NO_NETWORK=1)")

assert os.getuid() == NONROOT_UID, f"not nonroot uid {NONROOT_UID}: {os.getuid()}"
for forbidden in ("sh", "bash", "apk", "pip", "pip3", "busybox"):
    assert shutil.which(forbidden) is None, f"{forbidden} resolvable on PATH"
    assert not os.path.exists(f"/usr/bin/{forbidden}"), f"/usr/bin/{forbidden} present"
    assert not os.path.exists(f"/usr/sbin/{forbidden}"), f"/usr/sbin/{forbidden} present"
try:
    import pip  # noqa: F401
    raise AssertionError("pip module importable — must be absent")
except ImportError:
    pass

print(f"smoke ok: python {sys.version.split()[0]} "
      f"tls={'verified' if tls_ok else 'skipped(SMOKE_NO_NETWORK)'} "
      f"uid={os.getuid()} no-shell/apk/pip")
