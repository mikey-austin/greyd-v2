#
# Multi-stage build of greyd (Go port).
#
#   docker build -f packages/docker/Dockerfile -t mikeyaustin/greyd:go .
#
FROM golang:1.25-alpine AS build

RUN apk add --no-cache make

WORKDIR /src
COPY . /src

# The paths below are compiled into the programs, so the same values must
# be passed to both the build and the install.
RUN make build \
        DEFAULT_CONFIG=/usr/local/etc/greyd/greyd.docker.conf \
        GREYD_PIDFILE=/run/greyd/greyd.pid \
        GREYLOGD_PIDFILE=/run/greyd/greylogd.pid \
    && make install DESTDIR=/out \
        DEFAULT_CONFIG=/usr/local/etc/greyd/greyd.docker.conf \
        GREYD_PIDFILE=/run/greyd/greyd.pid \
        GREYLOGD_PIDFILE=/run/greyd/greylogd.pid

#
# Runtime image.
#
FROM alpine

RUN apk add --no-cache curl

COPY --from=build /out/usr/local /usr/local

EXPOSE 8025/tcp

# Root-owned runtime directory for the pidfiles (greyd writes them as root
# before dropping privileges); /tmp is world-writable and unsafe for them.
RUN mkdir -p /run/greyd && chmod 0755 /run/greyd
RUN ln -sf /dev/stdout /tmp/greyd.log
RUN addgroup -S greyd
RUN addgroup -S greydb
RUN adduser -HSD greyd greyd
RUN adduser -HSD greydb greydb

ENTRYPOINT [ "/usr/local/sbin/greyd", "-F" ]
