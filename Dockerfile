# syntax=docker/dockerfile:1

FROM debian:trixie-slim AS builder

ARG TARGETARCH
ARG VERSION_ARG="0.0"
ARG BRANCH_ARG="master"

ARG DEBCONF_NOWARNINGS="yes"
ARG DEBIAN_FRONTEND="noninteractive"
ARG DEBCONF_NONINTERACTIVE_SEEN="true"

RUN set -eu && \
    apt-get update && \
    apt-get --no-install-recommends -y install \
        git \
        alien \
        fakeroot \
        ca-certificates \
        build-essential && \
    apt-get clean && \
    git clone --depth 1 --branch "$BRANCH_ARG"  https://passt.top/passt /src && \
    cd src && patch -p1 < ../pad_frames.patch && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Override isolation code
COPY ./isolation.shim /src/isolation.c

WORKDIR /src

RUN set -eu && \
   make pkgs && \
   mv /src/*.deb /passt.deb

FROM debian:trixie-slim

ARG DEBCONF_NOWARNINGS="yes"
ARG DEBIAN_FRONTEND="noninteractive"
ARG DEBCONF_NONINTERACTIVE_SEEN="true"

COPY --from=builder /*.deb /

RUN set -eu && \
    dpkg -i /passt.deb && \
    apt-get update && \
    apt-get --no-install-recommends -y install \
        iputils-ping && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

ENTRYPOINT ["passt"]
