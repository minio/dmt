FROM golang:1.15 as golayer

RUN apt-get update -y && apt-get install -y ca-certificates

ADD go.mod /go/src/github.com/minio/route35/go.mod
ADD go.sum /go/src/github.com/minio/route35/go.sum
WORKDIR /go/src/github.com/minio/route35/

# Get dependencies - will also be cached if we won't change mod/sum
RUN go mod download

ADD . /go/src/github.com/minio/route35/
WORKDIR /go/src/github.com/minio/route35/

ENV CGO_ENABLED=0

RUN go build -ldflags "-w -s" -a -o route35 route35.go

FROM alpine

MAINTAINER MinIO Development "dev@min.io"

EXPOSE 8443

COPY --from=golayer /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=golayer /go/src/github.com/minio/route35/route35 .

ENTRYPOINT ["/route35"]
