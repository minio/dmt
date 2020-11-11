FROM scratch
MAINTAINER MinIO Development "dev@min.io"
EXPOSE 8443
COPY route35 /route35

ENTRYPOINT ["/route35"]
