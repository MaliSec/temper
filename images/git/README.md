# git: repository-cloning helper

git, the OpenSSH client and the CA bundle, nothing else. Use it for a
repository-clone step (for example a Kubernetes initContainer) in place of a
general-purpose image such as `alpine/git`.

## Package set

| package                 | purpose                                              |
|-------------------------|------------------------------------------------------|
| `wolfi-baselayout`      | minimal Wolfi filesystem layout                      |
| `ca-certificates-bundle`| TLS trust for https remotes (declared explicitly)    |
| `git`                   | git itself; fetch helpers in `/usr/libexec/git-core` |
| `openssh-client`        | `ssh` + `scp` for ssh:// remotes                     |

## Properties

- Distroless: no shell, no package manager, no busybox. A runtime image
  with busybox fails the hardening policy's shell check (policy §2), and
  git's clone/fetch path needs no shell.
- Runs as nonroot UID 65532.
- Empty OCI entrypoint: the caller names the git subcommand in exec form.
- `GIT_EXEC_PATH=/usr/libexec/git-core` is set so helpers resolve without a
  login shell.
- Built for `amd64` + `arm64`.

## Usage

```sh
# Run a clone directly (exec form, no shell):
docker run --rm -v "$PWD/out:/out" ghcr.io/malisec/temper/git:<tag> \
  clone --depth 1 https://github.com/org/repo.git /out/repo

# Or copy the tools into a derived image:
COPY --from=ghcr.io/malisec/temper/git@sha256:<digest> /usr/bin/git /usr/libexec/git-core /usr/bin/ssh /usr/bin/scp /overlays/git/
```

## Verification

- `scripts/check-policy.sh git`: nonroot, no setuid, no apk, no shell.
