# syntax=docker/dockerfile:1

FROM debian:trixie-slim AS builder

ARG TARGETARCH
ARG VERSION_ARG="0.0"
ARG BRANCH_ARG="master"

ARG DEBCONF_NOWARNINGS="yes"
ARG DEBIAN_FRONTEND="noninteractive"
ARG DEBCONF_NONINTERACTIVE_SEEN="true"

RUN <<EOF
  set -eu

  apt-get update
  apt-get --no-install-recommends -y install \
    git \
    alien \
    fakeroot \
    ca-certificates \
    build-essential

  apt-get clean

  # Clone passt
  git clone --depth 1 --branch "$BRANCH_ARG" https://passt.top/passt /src

  rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*
EOF

# Override isolation code
COPY ./isolation.shim /src/isolation.c

WORKDIR /src

RUN <<EOF
  set -eu

  # Build Debian package
  make pkgs
  mv /src/*.deb /passt.deb
EOF

FROM debian:trixie-slim

ARG DEBCONF_NOWARNINGS="yes"
ARG DEBIAN_FRONTEND="noninteractive"
ARG DEBCONF_NONINTERACTIVE_SEEN="true"

COPY --from=builder /*.deb /

RUN <<EOF
  set -eu

  # Install passt package
  dpkg -i /passt.deb

  apt-get update
  apt-get --no-install-recommends -y install \
    iputils-ping

  apt-get clean
  rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*
EOF

ENTRYPOINT ["passt"]
