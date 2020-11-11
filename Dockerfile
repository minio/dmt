FROM golang:1.15 as golayer

RUN apt-get update -y && apt-get install -y ca-certificates

ADD go.mod /go/src/github.com/minio/dmt/go.mod
ADD go.sum /go/src/github.com/minio/dmt/go.sum
WORKDIR /go/src/github.com/minio/dmt/

# Get dependencies - will also be cached if we won't change mod/sum
RUN go mod download

ADD . /go/src/github.com/minio/dmt/
WORKDIR /go/src/github.com/minio/dmt/

ENV CGO_ENABLED=0

RUN go build -trimpath -ldflags "-w -s" -a -o dmt .

FROM scratch

MAINTAINER MinIO Development "dev@min.io"

EXPOSE 8443

COPY --from=golayer /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=golayer /go/src/github.com/minio/dmt/dmt .

ENTRYPOINT ["/dmt"]
