# Maintaining Temper

How to cut a release.

## Cutting a release

`temper-nightly` releases `main` every night (02:17 UTC). To release by
hand, push a date tag on a commit on `main`:

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
