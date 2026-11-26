# Contributing to Temper

Temper is licensed under Apache-2.0. Contributions are accepted under the
same license.

## Sign your commits (DCO)

Temper uses the [Developer Certificate of Origin 1.1](https://developercertificate.org/).
There is no contributor license agreement and no copyright assignment: you
keep the copyright in your contribution, and you certify that you have the
right to submit it under the project license.

Add a `Signed-off-by` line to every commit:

```sh
git commit -s -m "static: bump ca-certificates-bundle"
```

That produces a trailer such as:

```
Signed-off-by: Your Name <you@example.com>
```

Pull requests with unsigned commits fail the DCO check. To fix an existing
branch, run `git rebase --signoff main` and force-push.

## Before you open a pull request

```sh
make lint        # yamllint over every YAML file
make validate    # structural YAML parse
make test        # policy and release-boundary tests (no registry, no keys)
```

If you change an image:

- Keep runtime images distroless: no shell, no package manager.
- Regenerate its lockfile with `make lock IMAGE=<name>` and commit it.
  `make test` fails if a lockfile's config checksum is stale.
- Run `make build-all && make policy` and include the result in the pull
  request description.
- Update the image's `README.md` if the package set or behaviour changes.

## Updating package versions

Each `apko.yaml` names package streams (for example `nodejs-26`); its
`apko.lock.json` pins the exact version of each package per architecture
(x86_64 and aarch64; every image ships both).
Builds and releases use only the lockfile. The packages built here
(`packages/`) pin their build toolchain in their recipes, so a rebuild
reproduces the package the `-fips` lockfiles pin; bump those pins, then
relock, to move them to a newer toolchain. Bump a recipe's `epoch` with
any change that changes its package (its files, its source, or the
toolchain), so each build of different contents has its own version in
the SBOMs and release records.

- **Automatic:** the `temper-nightly` workflow relocks every night, opens
  (or updates) one pull request, `relock/automated`, with the package diff,
  merges it once its required checks pass, and releases `main`. Run it by
  hand from the Actions tab, with an optional image name.
- **By hand:** `make lock IMAGE=node`, then `./scripts/lock-diff.sh` to see
  what moved. An image and its `-fips` variant always relock together.
  Images that use the `@local` repo lock against the packages built on the
  CI runners: a package records its directory sizes, which depend on the
  build filesystem. Relock them with `temper-nightly`.
- **Version lines:** `images/<name>` is the newest line of a repository;
  an older line is `images/<name>-<line>` (`images/node-24`) with a `repo`
  file naming the repository (`node`). It gets `<line>` and `<line>-<date>`
  tags only. To move to a new line, copy `images/<name>` to its old-line
  directory, edit the stream in `images/<name>`, relock both, and update
  the image README's Tags section. Delete an old-line directory to retire
  it; its line tag then stops receiving releases.

Image READMEs name packages, not versions. `make test` fails if a README
states a version that disagrees with the lockfile.

The `-fips` images are their base image plus the gofips packages
(`packages/`) and the environment variables that configure them;
`make test` fails if their package sets, accounts, environment or pinned
versions drift apart.

Every release produces the gofips evidence from its own commit and
attaches it as an attested bundle (`providers/gofips/docs/audit`, page
10). To see a change's effect before then, run
`providers/gofips/testdata/capture/run.sh <out-dir>`.

The release adds the line tags itself: an image's line comes from its
package stream (`scripts/image-line.sh`; `images/<name>/line` overrides
it). For an urgent fix, run `temper-nightly` by hand for the affected
image; it merges the relock once CI passes and releases.

## VEX statements

`vex/` holds an [OpenVEX](https://openvex.dev) file per vulnerability
(`vex/CVE-2026-1234.json`) saying how it affects each image repository.
Each statement names the package version it was checked against
(`pkg:apk/wolfi/glibc-2.44@2.44-r24`). When a relock moves the package,
the new version needs its own statement, checked again; keep the old one,
which still covers the releases that shipped that version.

- `not_affected` needs a justification and an impact statement giving
  the evidence (for example, which binaries were checked and how).
- `fixed` (the shipped package already contains the fix, though a
  scanner still reports it) needs status notes with the evidence: the
  upstream fix commit and how the shipped build was shown to contain it.
- `affected` needs an action statement: the fix status and what to do
  meanwhile. `under_investigation` needs status notes.
- Statements change what is reported, never what the release gate
  blocks: the gate runs on the scanners' raw findings.

`scripts/vex-check.sh` checks the files (`make test` runs it, and so does
each release, before publishing) and lists statements for package
versions no image ships now.

A statement can carry itself to new package versions. Give it evidence,
`vex/evidence/<CVE>.json`: the upstream project (`cpython` or `glibc`), the
issue (`gh-<number>` or `bz-<number>`) and fix commits, the status of each
package line (with the commits that fix it, for `fixed`), and a check that
exits 0 when the image is fixed and 1 when it is vulnerable:
`tests/vex/<CVE>.py`, run with the image's Python, or for glibc
`tests/vex/<CVE>.c`, built in `base-glibc-dev` and run in the image. Then:

- the nightly relock (`scripts/vex-carry.sh`) extends the statement to a
  new version when Wolfi's recipe for that version shows the same status:
  for `fixed`, it builds a commit containing a fix commit or cherry-picks
  one; for `affected`, nothing in its history mentions the issue; a
  `not_affected` statement is always extended, and rests on the check;
- CI (`tests/vex-checks.sh`) runs the check in every image that ships the
  package, on both architectures: a `fixed` or `not_affected` statement
  whose check shows the image vulnerable fails the build, and an
  `affected` one whose check shows it fixed warns.

A version the relock cannot carry is listed in its pull request; its
findings show as unreviewed until the statement is updated. Write the
check against the attack, not the code: it must show the image vulnerable
before the fix.

A change to `vex/` on main rebuilds the
[trust center](https://trust.malisec.dev), which applies the statements
to every release, including those cut before a statement was made. Each
release also attaches the statements as of its cut, as
`temper-<release>.vex.json`.

## What belongs here

In scope: image definitions, package recipes, the build, policy, scan,
signing and verification scripts, and their documentation.

Out of scope: vulnerabilities in upstream packages. Those are fixed upstream
and picked up by a rebuild; see [SECURITY.md](SECURITY.md).

## Maintainers

The release process is in [docs/maintaining.md](docs/maintaining.md).

## Reporting security issues

Do not open a public issue. Follow [SECURITY.md](SECURITY.md).
