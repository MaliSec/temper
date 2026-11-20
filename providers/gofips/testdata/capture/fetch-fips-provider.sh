#!/usr/bin/env bash
# fetch-fips-provider.sh: extract the genuine OpenSSL FIPS provider (fips.so)
# from Rocky Linux 10's openssl-fips-provider package, after checking the
# RPM's signature against Rocky's release key. Used by the parity capture
# (E-36). Usage: fetch-fips-provider.sh <output-dir>
set -euo pipefail
OUT="$(mkdir -p "${1:?usage: fetch-fips-provider.sh <output-dir>}" && cd "$1" && pwd)"
docker run --rm -e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)" -v "$OUT:/out" docker.io/rockylinux/rockylinux:10 bash -c '
  set -euo pipefail
  dnf -q -y install dnf-plugins-core cpio >/dev/null
  cd /tmp && dnf -q download openssl-fips-provider >/dev/null
  rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY-Rocky-10
  rpm -K *.rpm | grep -q "digests signatures OK" || { rpm -Kv *.rpm >&2; echo "RPM signature check failed" >&2; exit 1; }
  rpm -qp --qf "%{NAME}-%{VERSION}-%{RELEASE}\n" *.rpm > /out/fips.package
  rpm2cpio *.rpm | cpio -idm 2>/dev/null
  cp ./usr/lib64/ossl-modules/fips.so /out/fips.so
  chown "$HOST_UID:$HOST_GID" /out/fips.so /out/fips.package'
echo "fips.so ($(cat "$OUT/fips.package")) in $OUT"
