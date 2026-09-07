#
# Linux integration harness image for greyd (see run-linux.sh).
#
# Build from the repository root and run privileged, the container needs
# CAP_NET_ADMIN (ipset, NFLOG, conntrack, iptables), CAP_SYS_CHROOT and
# CAP_SETUID/SETGID (privilege separation):
#
#   docker build -f packages/integration/Dockerfile -t greyd-integration .
#   docker run --rm --privileged greyd-integration
#
# or simply "make test-integration".
#
FROM golang:1.25-bookworm

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        conntrack ipset iptables iproute2 netcat-openbsd procps python3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# Dependencies first so that source edits do not invalidate the module
# download layer.
COPY go.mod go.sum /src/
RUN go mod download

COPY . /src
RUN make build

ENTRYPOINT ["/src/packages/integration/run-linux.sh"]
