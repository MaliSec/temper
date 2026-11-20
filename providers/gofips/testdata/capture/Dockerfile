# Capture environment for the gofips evidence logs: Go 1.26.11, OpenSSL 4.0.3
# built from the verified release tarball, and the Docker CLI (the Node
# suites drive the host's daemon through its socket). See README.md.
FROM docker.io/library/golang:1.26.11

ARG OPENSSL_VERSION=4.0.3
# Docker's published repository signing key fingerprint.
ARG DOCKER_KEY_FPR=9DC858229FC7DD38854AE2D88D81803C0EBFCD88

RUN apt-get update -qq \
    && apt-get install -y -qq --no-install-recommends perl make pkg-config jq python3 binutils file xxd curl ca-certificates gnupg >/dev/null \
    && rm -rf /var/lib/apt/lists/*

# install_ssldirs also installs openssl.cnf; without it `openssl req` fails.
RUN cd /tmp && b=https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION} \
    && curl -fsSL -o o.tgz $b/openssl-${OPENSSL_VERSION}.tar.gz \
    && curl -fsSL -o o.sha $b/openssl-${OPENSSL_VERSION}.tar.gz.sha256 \
    && echo "$(cut -d' ' -f1 o.sha)  o.tgz" | sha256sum -c - \
    && tar xzf o.tgz && cd openssl-${OPENSSL_VERSION} \
    && ./Configure --prefix=/usr/local --libdir=lib no-tests no-docs >/dev/null \
    && make -j"$(nproc)" >/dev/null && make install_sw install_ssldirs >/dev/null \
    && ldconfig && cd / && rm -rf /tmp/o.tgz /tmp/o.sha /tmp/openssl-${OPENSSL_VERSION}

RUN curl -sSfL -o /tmp/docker.asc https://download.docker.com/linux/debian/gpg \
    && gpg --show-keys --with-colons /tmp/docker.asc | awk -F: '$1 == "fpr" {print $10}' | grep -qx "$DOCKER_KEY_FPR" \
    && gpg --dearmor -o /usr/share/keyrings/docker.gpg /tmp/docker.asc \
    && . /etc/os-release \
    && echo "deb [arch=amd64 signed-by=/usr/share/keyrings/docker.gpg] https://download.docker.com/linux/debian ${VERSION_CODENAME} stable" \
        > /etc/apt/sources.list.d/docker.list \
    && apt-get update -qq && apt-get install -y -qq --no-install-recommends docker-ce-cli >/dev/null \
    && rm -rf /var/lib/apt/lists/* /tmp/docker.asc

RUN openssl version && go version && docker --version
