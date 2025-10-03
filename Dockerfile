# syntax=docker/dockerfile:1

FROM debian:trixie-slim AS builder

ARG VERSION_ARG="0.0"
ARG BRANCH_ARG="master"
ARG TARGETOS TARGETARCH

ARG DEBCONF_NOWARNINGS="yes"
ARG DEBIAN_FRONTEND="noninteractive"
ARG DEBCONF_NONINTERACTIVE_SEEN="true"

RUN set -eu && \
    apt-get update && \
    apt-get --no-install-recommends -y install \
        git \
        ca-certificates \
        build-essential && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

RUN mkdir /src && git clone --depth 1 --branch "$BRANCH_ARG"  https://passt.top/passt /src
COPY ./isolation.c /src/
WORKDIR /src

RUN make pkgs
RUN ./passt

FROM scratch

COPY --chmod=755 --from=builder /passt /passt

ENTRYPOINT ["/passt"]
