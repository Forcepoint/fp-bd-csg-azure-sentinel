FROM golang:alpine as builder
RUN mkdir /build
ADD . /build/
WORKDIR /build
RUN CGO_ENABLED=0 GOOS=linux go build -mod=vendor  -a -installsuffix cgo -ldflags '-extldflags "-static"' -o scg-sentinel .
FROM scratch
FROM docker.frcpnt.com/fp-dep-log-exporter-client-base:latest
MAINTAINER dlo.bagari@forcepoint.com
ENV tmpdir /opt
COPY --from=builder /build/scg-sentinel /opt/scg-sentinel
COPY main.sh $tmpdir/
WORKDIR ${tmpdir}
RUN chmod 775 $tmpdir/*.sh; sync
RUN mkdir /root/csg-timer
CMD ["sh", "-c", "/opt/main.sh"]