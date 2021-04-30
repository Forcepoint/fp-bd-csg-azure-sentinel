FROM golang:alpine as builder
RUN mkdir /build
ADD . /build/
WORKDIR /build
RUN CGO_ENABLED=0 GOOS=linux go build -mod=vendor  -a -installsuffix cgo -ldflags "-X 'main.encryptionKey=' -extldflags '-static'" -o csg-sentinel .
FROM scratch
FROM ubuntu
RUN apt update &&\
 apt install -y apt-utils &&\
 apt install -y wget &&\
 apt install -y python &&\
 apt install curl -y &&\
 apt install rsyslog -y &&\
 apt install -y gpg &&\
 apt install -y sudo
MAINTAINER dlo.bagari@forcepoint.com
ENV tmpdir /opt
COPY --from=builder /build/csg-sentinel /opt/csg-sentinel
COPY main.sh $tmpdir/
WORKDIR ${tmpdir}
RUN chmod 775 $tmpdir/*.sh; sync
CMD ["sh", "-c", "/opt/main.sh"]