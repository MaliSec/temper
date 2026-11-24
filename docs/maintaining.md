# Maintaining Temper

How to cut a release, move `latest` back, bump a package's build environment,
and release another repository's images.

## Cutting a release

`temper-nightly` releases `main` every night. It is scheduled for 02:17 UTC,
but GitHub starts scheduled runs late under load, often by hours, and can
skip one; `gh workflow run temper-nightly.yml --ref main` starts it by hand.
To release by hand, push a date tag on a commit on `main`:

```sh
git tag -s 2026.11.19 -m "Temper 2026.11.19"
git push origin 2026.11.19
```

The date must be today or yesterday (UTC). A second release on the same
day is `2026.11.19.1`. The workflow builds, scans, publishes, signs,
verifies, tags and writes a GitHub release with the signed manifest.

## Moving `latest` back

If the release `latest` points at is bad, point `latest` and the line tags
back at the last good release:

```sh
docker login ghcr.io                                    # write access to the packages
./scripts/rollback-latest.sh <good-date-tag> --dry-run  # shows what would move
./scripts/rollback-latest.sh <good-date-tag>
```

The script checks that the good release's manifest is signed by the
release workflow and verifies every image in it before moving anything; if
a check fails, nothing moves. Leave the bad release's date tags in place,
say in its release notes that it was rolled back, and ship the fix as a
new release.

## Bumping a package's build environment

Each `packages/<name>/melange.yaml` pins its whole build environment: the
packages it lists, and below the `pin-build-env.sh` marker, everything they
pull in. melange records that environment in the package, and the
lockfiles pin the package by checksum, so a floating version would fail
every build against the lockfiles as soon as Wolfi updated it. The nightly
relock does not change these pins.

To bump, edit the versions above the marker if needed, then repin and
relock:

```sh
./scripts/pin-build-env.sh   # unpins, builds the packages, pins what resolved
./scripts/build.sh --lock
```

Wolfi keeps a version for about six months. Bump before then: once a pinned
version is gone, the package no longer builds.

## Releasing another repository's images

Another repository (for example `MaliSec/temper-apps`) releases its images
through the composite actions in `.github/actions`, pinned to a Temper
commit. It gets the same build, policy check, vulnerability gate, signing,
provenance, SBOMs, manifest and `latest`/line tags. Each action runs the
scripts from its own checkout of Temper on the calling repository's
`images/`, `packages/` and `vex/`. The scanners read Temper's empty
`scripts/scanners.yaml`, so a `.trivyignore` or `.grype.yaml` in the
calling repository changes nothing.

### The repository

- `project.env` (see `scripts/project.sh`):

  ```sh
  name=temper-apps
  title=Temper Apps
  repo=MaliSec/temper-apps
  release_workflow=temper-apps-release.yml
  images=ghcr.io/malisec/temper-apps
  ```

  `images` is a namespace of its own. A workflow's token can push only to
  packages its repository created or was given access to, and a new
  package belongs to whichever repository pushes it first. In a shared
  namespace, any repository in the organisation could take an image's
  name first.
- `images/<name>/apko.yaml` for each image, with its committed lockfile
  (`apko.lock.json`): the release builds from the lockfiles and resolves
  nothing. Generate them from a Temper checkout, building the project's
  packages first when an image uses them:

  ```sh
  TEMPER_PROJECT_DIR=../temper-apps ./scripts/build.sh --packages
  TEMPER_PROJECT_DIR=../temper-apps ./scripts/build.sh --lock
  ```

- At least one package in `packages/<name>/melange.yaml`, and a `vex/`
  directory (a `.gitkeep` is enough to start with).
- The release workflow below, saved under the name in `release_workflow`.
- A tag ruleset, like Temper's `tag-main`, that limits who can create,
  update or delete date tags, and a `main` ruleset that requires pull
  requests and blocks force pushes. The release accepts any date tag on a
  commit on `main`, so these rulesets decide what gets released.
- If the organisation allows only selected actions, allow actions created
  by GitHub (`actions/checkout`, `actions/upload-artifact`,
  `actions/download-artifact`, `actions/attest`) and add
  `MaliSec/temper/.github/actions/*`. Temper is public, so nothing else is
  needed for another repository to use its actions.

### The release workflow

The jobs and their permissions must be in this workflow, because a
signature names the workflow that ran the job, not the action. Its
releases carry their own signer identity,
`https://github.com/MaliSec/temper-apps/.github/workflows/temper-apps-release.yml@refs/tags/<tag>`,
and their own source repository. Temper's verification refuses both, and
the other repository's verification refuses Temper's. Don't call Temper's
`temper-release-build.yml` from another repository.

The workflow runs on the tag push itself, so no other workflow can call
it. Each job also checks the repository, so a fork that pushes a date tag
releases nothing.

```yaml
name: temper-apps-release
on:
  push:
    tags:
      - '[0-9][0-9][0-9][0-9].[0-9][0-9].[0-9][0-9]'
      - '[0-9][0-9][0-9][0-9].[0-9][0-9].[0-9][0-9].[1-9]'
      - '[0-9][0-9][0-9][0-9].[0-9][0-9].[0-9][0-9].[1-9][0-9]+'
permissions:
  contents: read
# One release at a time, so two runs cannot both move latest. Further
# tags wait their turn instead of replacing each other.
concurrency:
  group: temper-apps-release
  cancel-in-progress: false
  queue: max
jobs:
  packages:
    if: github.repository == 'MaliSec/temper-apps'
    strategy:
      matrix:
        include:
          - { arch: x86_64, runner: ubuntu-24.04 }
          - { arch: aarch64, runner: ubuntu-24.04-arm }
    runs-on: ${{ matrix.runner }}
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - uses: MaliSec/temper/.github/actions/packages@<temper commit>
        with:
          arch: ${{ matrix.arch }}
  build:
    if: github.repository == 'MaliSec/temper-apps'
    needs: packages
    runs-on: ubuntu-24.04
    permissions:
      contents: read
      packages: write
    outputs:
      images: ${{ steps.publish.outputs.images }}
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          fetch-depth: 0
      - id: publish
        uses: MaliSec/temper/.github/actions/publish@<temper commit>
  attest:
    if: github.repository == 'MaliSec/temper-apps'
    needs: build
    runs-on: ubuntu-24.04
    permissions:
      contents: read
      packages: write
      id-token: write
      attestations: write
      artifact-metadata: write
    strategy:
      matrix:
        image: ${{ fromJSON(needs.build.outputs.images) }}
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - uses: MaliSec/temper/.github/actions/attest@<temper commit>
        with:
          repository: ${{ matrix.image.repository }}
          digest: ${{ matrix.image.digest }}
          sbom: ${{ matrix.image.sbom }}
  release:
    if: github.repository == 'MaliSec/temper-apps'
    needs: [build, attest]
    runs-on: ubuntu-24.04
    permissions:
      contents: write
      packages: write
      id-token: write
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - uses: MaliSec/temper/.github/actions/release@<temper commit>
```

### Verifying its images

From a checkout of Temper at the pinned commit, with `TEMPER_PROJECT_DIR`
set to a checkout of the other repository at the release tag. Download the
manifest and its signature bundle first; the bundle must sit beside it:

```sh
gh release download <tag> --repo MaliSec/temper-apps \
  --pattern 'temper-apps-<tag>.manifest.yaml*'
TEMPER_PROJECT_DIR=../temper-apps ./scripts/verify-build.sh <name> \
  --date <tag> --manifest temper-apps-<tag>.manifest.yaml
```

`<name>` is the image's repository: an older version line
(`images/<dir>/repo` names the primary image) publishes there, tagged
`<line>-<tag>`, so pass `--date <line>-<tag>`. The script prints the signer
and source repository it checks against.
