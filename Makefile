PWD := $(shell pwd)
GOPATH := $(shell go env GOPATH)
# Sets the build version based on the output of the following command, if we are building for a tag, that's the build else it uses the current git branch as the build
BUILD_VERSION:=$(shell git describe --exact-match --tags $(git log -n1 --pretty='%h') 2>/dev/null || git rev-parse --abbrev-ref HEAD 2>/dev/null)
BUILD_TIME:=$(shell date 2>/dev/null)
TAG ?= "minio/dmt:$(VERSION)-dev"

default: dmt

.PHONY: dmt
dmt:
	@echo "Building dmt binary to './dmt'"
	@(GO111MODULE=on CGO_ENABLED=0 go build -trimpath --tags=kqueue --ldflags "-s -w" -o dmt ./dmt.go)

getdeps:
	@mkdir -p ${GOPATH}/bin
	@which golangci-lint 1>/dev/null || (echo "Installing golangci-lint" && curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(GOPATH)/bin v1.27.0)

verifiers: getdeps fmt lint

fmt:
	@echo "Running $@ check"
	@GO111MODULE=on gofmt -d .

lint:
	@echo "Running $@ check"
	@GO111MODULE=on ${GOPATH}/bin/golangci-lint cache clean
	@GO111MODULE=on ${GOPATH}/bin/golangci-lint run --timeout=5m --config ./.golangci.yml

install: dmt
	@echo "Installing dmt binary to '$(GOPATH)/bin/dmt'"
	@mkdir -p $(GOPATH)/bin && cp -f $(PWD)/dmt $(GOPATH)/bin/dmt
	@echo "Installation successful. To learn more, try \"dmt --help\"."

clean:
	@echo "Cleaning up all the generated files"
	@find . -name '*.test' | xargs rm -fv
	@find . -name '*~' | xargs rm -fv
	@rm -vf dmt

docker:
	@docker build -t $(TAG) --build-arg build_version=$(BUILD_VERSION) --build-arg build_time='$(BUILD_TIME)' .
