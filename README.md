# Temper

Hardened, signed container base images, built from
[Wolfi](https://wolfi.dev/) packages with
[apko](https://github.com/chainguard-dev/apko).

Temper is free to use for your own workloads. It is open source under
Apache-2.0. There is no paid tier, no support contract and no guaranteed
patch time.

## Images

| Image | Kind | For |
|---|---|---|
| `static` | Runtime | Single-binary programs with no C library, such as Go and Rust |
| `base-glibc` | Runtime | Programs that need the standard C library |
| `node` | Runtime | Node.js applications (Node.js 26; Node.js 24 as `node:24`) |
| `python` | Runtime | Python applications (Python 3.14; Python 3.13 as `python:3.13`) |
| `node-fips` | Runtime, FIPS | `node` with OpenSSL's cryptography served by the gofips provider over the Go Cryptographic Module (CMVP #5247) |
| `python-fips` | Runtime, FIPS | `python` with OpenSSL's cryptography served by the gofips provider over the Go Cryptographic Module (CMVP #5247) |
| `git` | Runtime helper | Cloning repositories: git, the OpenSSH client and CA certificates |
| `base-glibc-dev` | Build | Compilers and headers for build stages |
| `go-builder` | Build | Go toolchain for build stages |
| `node-builder` | Build | Node.js and npm for build stages |
| `base-shell` | Debug | A shell for troubleshooting |

Every image is published for `linux/amd64` and `linux/arm64` as one
multi-arch image index; tags and digests name the index, and a pull picks
the platform. Both architectures are built, policy-checked and tested
natively in CI.

Build and debug images carry a shell and are never a production base. Each
image's directory under `images/` has its own README with the package set
and usage.

The `-fips` images load only the gofips OpenSSL provider
([providers/gofips](providers/gofips/README.md)), so OpenSSL has no other
provider to fall back to. They serve a narrower set of algorithms than
their base images: TLS 1.3, and TLS 1.2 with AES-GCM only; no RSA private
keys, no MD5. Their READMEs list what is served and what is refused.

## How images are hardened

Every build is checked by `scripts/check-policy.sh`. A violation fails the
build, and nothing from it is published.

- Runs as an unprivileged user (uid 65532).
- No setuid or setgid files anywhere in the image.
- No package manager and no shell in runtime images.
- Every package version pinned in a committed lockfile
  (`images/<name>/apko.lock.json`).

The full policy is in [policy/security-policy.md](policy/security-policy.md).

## How a release is cut

Each step must pass before the next runs:

```
build ──► policy check ──► vulnerability scan ──► push by digest ──► sign + attest ──► verify ──► tag ──► release manifest
```

- **Scan before publish.** A critical or known-exploited finding stops the
  release. Images are pushed by digest and get their tags only after they
  verify.
- **Signed and attested.** Each image carries a signature, an SPDX SBOM and
  SLSA Build Level 3 provenance tying its digest to the source commit, which
  pins the lockfiles.
- **Immutable date tags, gated `latest` and line tags.** A published date
  tag is never rewritten. Images with a version line also get `<line>-<date>`
  (`node:26-2026.11.19`), equally immutable. `latest` follows the newest
  release that passed every gate, and each line tag (`node:26`, `node:24`,
  `python:3.14`, `python:3.13`, `go-builder:1.26`) the newest release on that
  line. Pin by digest for reproducible builds.
- **Release manifest.** Each cut produces a manifest listing every image's
  digest and scan counts, and a scans file with every finding behind them.
  Both are published on the release for that date tag, with the manifest
  signed and recording the scans file's sha256; neither is committed to
  this repository.

## Verify an image

Verification needs only public material and no Temper key. The signature
check needs no account; the attestation checks use the GitHub CLI, which
needs a GitHub login. See [docs/verifying.md](docs/verifying.md).

```sh
./scripts/verify-build.sh ghcr.io/malisec/temper/static@sha256:<digest>
```

## Build locally

```sh
make install-tools        # apko, melange, cosign, crane, grype, syft, trivy (checksum-pinned)
make build-all            # images into dist/ (git-ignored)
make policy               # hardening policy check, fail-closed
make scan                 # vulnerability scan gate, Trivy + Grype (no criticals or known-exploited)
make test                 # policy and release-boundary tests
```

## Repository layout

```
images/<name>/        apko image definitions and committed lockfiles
packages/<name>/      melange recipes for packages built here
providers/gofips/     the gofips OpenSSL provider and its audit pack
scripts/              build, policy check, release cut and verify scripts
policy/               security and hardening policy
docs/                 verifying images, third-party software
tests/                local test suite
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Commits must carry a DCO sign-off.

## Security

Report vulnerabilities privately; see [SECURITY.md](SECURITY.md).

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

The images contain third-party packages under their own licenses; see
[docs/third-party.md](docs/third-party.md). Wolfi is a trademark of its
owner. Temper is not affiliated with or endorsed by Chainguard.
