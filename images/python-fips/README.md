# Python FIPS runtime base image

The `python` image with the gofips OpenSSL provider. `hashlib`, `hmac` and
`ssl` run in the Go Cryptographic Module (CMVP #5247), except SHA-1 and the
AES-CBC that encrypts TLS session tickets (see below). The default and
legacy OpenSSL providers are not loaded, so an operation gofips does not
serve fails instead of falling back.

Everything else (packages, versions, user, environment) is the
`python` image; `make test` keeps them identical.

## FIPS claim

The image relies on CMVP #5247 for the operations listed as served below.
gofips passes calls to the validated module unmodified. What the reliance
rests on, and the evidence for each condition, is in the gofips audit pack
([providers/gofips/docs/audit](../../providers/gofips/docs/audit/README.md)).

The configuration that makes this hold is set in the image:

- `OPENSSL_CONF=/etc/ssl/openssl-gofips.cnf` loads gofips and `base` only.
- `GODEBUG=fips140=on` runs the Go module in approved mode.
- Package `temper-python-3.14-fips` (`temper-python-3.13-fips` in
  `python-fips:3.13`) closes CPython's paths around the provider. BLAKE2,
  which CPython implements itself, is replaced by a module that refuses.
  Python 3.14's built-in HMAC (`_hmac`), which `hmac` falls back to when
  OpenSSL refuses, is removed. The standard `hmac` module is replaced by
  one that computes every HMAC through the provider's HMAC; the standard
  module would otherwise compute HMAC itself (pure Python, or OpenSSL's
  legacy `HMAC_CTX`). It is a module file, not a startup hook, so it holds
  in virtualenvs, with `python -S`, and whatever `sitecustomize` an
  application adds. An `HMAC` object keeps its message in memory until
  `digest()`.

Changing any of these, or loading another provider, takes the image outside
the claim. Third-party packages with their own cryptography (for example
`cryptography` wheels, which bundle their own OpenSSL, or pure-Python
implementations) are outside it too.

## Served

| Area | Algorithms |
|---|---|
| `hashlib` | `sha256`, `sha384`, `sha512`, `sha3_224/256/384/512`, `shake_128`, `shake_256` |
| `hmac` | `hmac.new`, `hmac.digest`: SHA-2 or SHA-3 hash, keys of 112 bits or more |
| `hashlib.pbkdf2_hmac` | salt of 128 bits or more, derived key of 112 bits or more, SHA-2 or SHA-3 |
| `ssl` | TLS 1.3, and TLS 1.2 with AES-GCM and the extended master secret; see below |

`hashlib.sha1` is served for non-security uses and is not approved.
`secrets` and `os.urandom` read the kernel's random source, as in any
Python image; they do not go through OpenSSL and are outside the claim.

## Refused

These raise `ValueError`:

- `md5`, `md4`, `ripemd160`, `sha224`, `sha512_256`, `blake2b`, `blake2s`.
- `pbkdf2_hmac` with a short salt or key, or with `sha1`.
- HMAC with a key under 112 bits, or with `sha1` or `md5`.
- HMAC with a `digestmod` that is neither a hash name nor a callable
  returning an OpenSSL hash (for example a module, or a callable returning
  another object): the standard module would compute it in pure Python.

`hashlib.algorithms_available` still lists `blake2b` and `blake2s`: CPython
reports them unconditionally.

`ssl` refuses TLS 1.1 and below, TLS 1.2 CBC suites and TLS 1.2 without
the extended master secret, RSA private keys, and curves other than P-256
and P-384.

## TLS

TLS 1.3, and TLS 1.2 with AES-GCM and the extended master secret
(RFC 7627), with P-256 or P-384 key exchange and server certificates that
are ECDSA (P-256, P-384) or RSA (2048 bits or more), in chains signed with
ECDSA or RSA (PKCS#1 v1.5 or PSS) and SHA-2. Most public HTTPS services meet
this; the smoke test connects to packages.wolfi.dev (TLS 1.3) and
registry.npmjs.org (TLS 1.2) with verified chains. Session tickets and
resumption work, as client and as server.

A connection fails when the server:

- supports only TLS 1.1 or older, or TLS 1.2 without AES-GCM or without
  the extended master secret;
- presents a P-521 or Ed25519 certificate, or a chain with a SHA-1
  signature, an RSA key under 2048 bits, or an RSA public exponent below
  65537;
- requires a client certificate with an RSA key (this image can hold only
  ECDSA private keys).

## Use

    FROM ghcr.io/malisec/temper/python-fips@sha256:<digest>
    COPY --chown=65532:65532 app/ /app/
    ENTRYPOINT ["/usr/bin/python3.14", "/app/main.py"]

`tests/smoke-python-fips.py` checks the served and refused lists above.

## fork()

The provider runs in a Go runtime inside the process, and Go does not
support `fork()` without `exec`: a forked child that uses crypto can hang
on a lock the runtime held at the fork. It is most likely while other
threads use crypto (about one child in four in testing), and no state of
the parent makes it safe.

- `multiprocessing` defaults to `forkserver` on both lines (Python 3.14
  does; on 3.13 the image sets it). `set_start_method("fork")` brings the
  risk back.
- Servers that fork workers (gunicorn, Celery's prefork pool, uWSGI) are
  exposed, most of all when threads use crypto while workers are forked.
  Loading the application in each worker reduces this but does not remove
  it: the master loads the provider as soon as it imports `hashlib` or
  creates a TLS context. To avoid it, run one process per container and scale with
  threads or replicas (for example gunicorn `--workers 1 --threads N`, or
  Celery's `threads` pool), or use a server that starts each worker as a
  new process.
- Node.js is not affected: `child_process` and `cluster` start new
  processes.

## Tags

Two lines are published in this repository: 3.14 (the newest stable line, this
directory) and 3.13 (security fixes until 2029, `images/python-fips-3.13`).

- `python-fips:3.14` follows the newest release on the 3.14 line (forward only).
- `python-fips:3.13` follows the newest release on the 3.13 line (forward only).
- `python-fips:3.14-YYYY.MM.DD`, `python-fips:3.13-YYYY.MM.DD` and
  `python-fips:YYYY.MM.DD` (the 3.14 line) never move.
- `python-fips:latest` follows the newest release of the 3.14 line.

Pin a digest for reproducible builds.
