# Security Policy

Temper publishes free, open source container images. This file is the
project's coordinated vulnerability disclosure policy.

## Supported versions

Temper is fix-forward. Each release is published under an immutable date
tag (e.g. `2026.11.19`) and pinned digests (`repo@sha256:...`). There is no
LTS track and no backporting.

- **Immutable date tags and pinned digests** are the supported surface.
  Rebuilds get new date tags; a published tag is never rewritten.
- **`latest`** follows the newest release that passed every gate. Use it to
  pick up fixes automatically; pin a date tag or digest for reproducible
  builds. A release never moves it backwards; only a verified rollback
  (below) points it at an earlier release.
- **Line tags** (`node:26`, `node:24`, `python:3.14`, `go-builder:1.26`)
  follow the newest release on that version line, forward only, and
  `<line>-<date>` (`node:24-2026.11.19`) is immutable. `node`, `node-builder`,
  `node-fips`, `python` and `python-fips` publish two lines; the date tag
  and `latest` follow the newer one. When a line is retired, its line tag
  stops receiving releases; the release notes say so.
- **`:debug` variants** are not published. Build them locally for
  troubleshooting (see each image's README); they are not supported for
  production.

If an image you run has a known vulnerability, move to the newest date tag
and digest. There is no backport to wait for.

## Reporting a vulnerability

Do not open a public issue for a security vulnerability.

Report privately through GitHub: open the repository's **Security** tab and
choose **Report a vulnerability**. That opens a private advisory visible only
to you and the maintainers.

If you cannot use GitHub, email **security@malisec.dev**.

Include:

- The affected image and the exact tag or digest you run.
- Where you got the image (GHCR, a mirror, etc.).
- A description of the vulnerability, including any exploit scenario.
- A fix or patch, or a link to one, if you have it.
- The affected components (Wolfi package, our recipe, our CI, upstream).

## Response expectations

- **Acknowledgment** within 3 business days.
- **Triage** (scope and severity confirmed) within 10 business days.
- **Coordinated disclosure**: we agree a disclosure date with you. The
  standard timeline is 90 days from acknowledgment, shorter for actively
  exploited or critical issues.

## Handling process

1. Triage: decide whether the issue is in our recipes or pipeline, or in
   upstream Wolfi packages. Upstream issues are fixed upstream, not by us.
2. Fix: for our recipes or pipeline, ship a rebuilt image under a new date
   tag with the fixed packages pinned.
3. Evidence: every rebuild carries its own signed SBOM and provenance, and
   its scan results are recorded in the release manifest for that date tag
   (see [docs/verifying.md](docs/verifying.md)).
4. Disclosure: coordinate the public write-up with the reporter, with credit
   if requested.

## Rolling back latest

A bad release that `latest` points at is rolled back as in
[docs/maintaining.md](docs/maintaining.md#moving-latest-back).

## Scope

**In scope:** images, melange recipes, apko configs, the build, sign and scan
pipeline, and documentation in this repository.

**Out of scope (fix upstream):** vulnerabilities in Wolfi packages (report
to Chainguard/Wolfi), in apko or melange, in the Linux kernel, or in
third-party application code bundled into an image. We rebuild and repin; we
do not patch upstream.

## Safe harbor

We will not pursue legal action (including DMCA takedowns) against
researchers acting in good faith who:

- Report through this policy,
- Do not exploit vulnerabilities beyond what is necessary to demonstrate them,
- Do not access, modify, or destroy data they do not own,
- Stop testing upon our request.

## Legal

Copyright 2026 Maligator Software, Inc. Licensed under the Apache License,
Version 2.0 (see [LICENSE](LICENSE)).
