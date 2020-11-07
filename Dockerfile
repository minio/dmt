FROM scratch
MAINTAINER MinIO Development "dev@min.io"
EXPOSE 8443
COPY reverse /reverse

ENTRYPOINT ["/reverse"]
