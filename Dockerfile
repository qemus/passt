# syntax=docker/dockerfile:1

FROM debian:trixie-slim AS builder

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
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Override isolation code
COPY ./isolation.c /src/

WORKDIR /src

RUN set -eu && \
   make pkgs && \
  ./passt && \
   mv /src/*.deb /passt_${VERSION_ARG}_all.deb && \
   mv /src/*.rpm /passt_${VERSION_ARG}.x86_64.rpm && \
   ln -s /passt_${VERSION_ARG}_all.deb /passt.deb && \
   ln -s /passt_${VERSION_ARG}.x86_64.rpm /passt.rpm

FROM debian:trixie-slim

ARG DEBCONF_NOWARNINGS="yes"
ARG DEBIAN_FRONTEND="noninteractive"
ARG DEBCONF_NONINTERACTIVE_SEEN="true"

RUN set -eu && \
    dpkg -i /passt.deb && \
    apt-get --no-install-recommends -y install \
        iputils-ping && \
    apt-get clean && \
    passt && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

ENTRYPOINT ["passt"]
