# Third-party software

Temper's own files (image definitions, recipes, scripts and documentation)
are licensed under Apache-2.0. The images those files produce contain
software written by other people, under other licenses.

## What is inside an image

Every package in a Temper image comes from the
[Wolfi](https://wolfi.dev) package repository, except the packages built
here from `packages/` for the `-fips` images. Each package keeps its
upstream license. Examples from the current image family:

| Package | Found in | License |
|---|---|---|
| `glibc` | `base-glibc` and images built on it | LGPL-2.1-or-later |
| `busybox` | `base-shell`, builder and debug images | GPL-2.0-only |
| `nodejs` | `node`, `node-builder`, `node-fips` | MIT |
| `go` | `go-builder` | BSD-3-Clause |
| `rust` | `rust-builder` | Apache-2.0 AND MIT |
| `python` | `python`, `python-fips` | PSF-2.0 |
| `git` | `git`, `go-builder`, `rust-builder` | GPL-2.0-or-later (with Perl components under Artistic-1.0-Perl or GPL-1.0-or-later) |
| `ca-certificates-bundle` | every image | MPL-2.0 and MIT |
| `libgcc` | glibc-based images | GPL-3.0-or-later with the GCC runtime exception |
| `bash`, `make`, `binutils` | `go-builder`, `rust-builder` | GPL-3.0-or-later |
| `gcc` | `go-builder`, `rust-builder` | GPL-3.0-or-later with the GCC runtime exception |
| `npm` | `node-builder` | Artistic-2.0 |
| `temper-gofips` | `node-fips`, `python-fips` | Apache-2.0; contains the Go standard library and runtime (BSD-3-Clause) |
| `temper-python-3.14-fips`, `temper-python-3.13-fips` | `python-fips` | Apache-2.0 |
| `temper-node-fips` | `node-fips` | Apache-2.0 |

Licenses are as declared in the Wolfi package index. This table is
illustrative, not complete, and goes stale as packages change. The
authoritative list for any image is its SBOM.

## Finding the license of everything in an image

Each published image carries an SPDX SBOM as a signed attestation, bound to
the image digest. It lists every package, its version and its declared
license. See [verifying.md](verifying.md) for how to retrieve and check it.

## Source code

The build definition for every Wolfi package, including the upstream source
location and any patches, is public at
[github.com/wolfi-dev/os](https://github.com/wolfi-dev/os). The committed
`apko.lock.json` beside each image definition pins the exact package
versions an image was built from.

If you need the source for a package in a Temper image and cannot find it
through those two routes, open an issue.

## Build and release tools

Temper's pipeline invokes these tools; it does not redistribute them:

| Tool | Used for | License |
|---|---|---|
| [apko](https://github.com/chainguard-dev/apko) | assembling images | Apache-2.0 |
| [melange](https://github.com/chainguard-dev/melange) | building packages | Apache-2.0 |
| [cosign](https://github.com/sigstore/cosign) | signing and attestations | Apache-2.0 |
| [crane](https://github.com/google/go-containerregistry) | registry operations | Apache-2.0 |
| [syft](https://github.com/anchore/syft) | SBOM generation | Apache-2.0 |
| [grype](https://github.com/anchore/grype) | vulnerability scanning | Apache-2.0 |
| [trivy](https://github.com/aquasecurity/trivy) | vulnerability scanning | Apache-2.0 |

## Trademarks

Wolfi and the other names above are trademarks of their respective owners.
Temper is an independent project. It is not affiliated with, sponsored by or
endorsed by Chainguard or any other project named here.
