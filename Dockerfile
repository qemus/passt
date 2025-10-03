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

RUN make pkgs
RUN ./passt

FROM scratch

COPY --chmod=755 --from=builder /src/passt /passt/
COPY --chmod=755 --from=builder /src/passt.1 /passt/
COPY --chmod=755 --from=builder /src/passt.avx2 /passt/
COPY --chmod=755 --from=builder /src/pasta /passt/
COPY --chmod=755 --from=builder /src/pasta.1 /passt/
COPY --chmod=755 --from=builder /src/pasta.avx2 /passt/
COPY --chmod=755 --from=builder /src/qrap /passt/
COPY --chmod=755 --from=builder /src/qrap.1 /passt/
COPY --chmod=755 --from=builder /src/passt-repair /passt/
COPY --chmod=755 --from=builder /src/passt-repair.1 /passt/

ENTRYPOINT ["/passt/passt"]
