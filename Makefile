NAME=louketo-proxy
AUTHOR=louketo
REGISTRY=docker.io
CONTAINER_TOOL=$(shell command -v podman 2>/dev/null || command -v docker)
ROOT_DIR=${PWD}
HARDWARE=$(shell uname -m)
GIT_SHA=$(shell git --no-pager describe --always --dirty)
BUILD_TIME=$(shell date '+%s')
VERSION ?= $(shell awk '/release.*=/ { print $$3 }' doc.go | sed 's/"//g')
DEPS=$(shell go list -f '{{range .TestImports}}{{.}} {{end}}' ./...)
PACKAGES=$(shell go list ./...)
LFLAGS ?= -X main.gitsha=${GIT_SHA} -X main.compiled=${BUILD_TIME}
VETARGS ?= -asmdecl -atomic -bool -buildtags -copylocks -methods -nilfunc -printf -rangeloops -shift -unsafeptr
PLATFORMS=darwin linux windows
ARCHITECTURES=amd64


default: build

.PHONY: golang build static
golang:
	@echo "--> Go Version"
	@go version

build: golang
	@echo "--> Compiling the project"
	@mkdir -p bin
	go build -ldflags "${LFLAGS}" -o bin/${NAME}

static: golang
	@echo "--> Compiling the project statically"
	@mkdir -p bin
	CGO_ENABLED=0 GOOS=linux go build -a -tags netgo -ldflags "-w ${LFLAGS}" -o bin/${NAME}

.PHONY: container-build docker-build
container-build: docker-build
docker-build:
	@echo "--> Compiling the project, inside a temporary container"
	$(eval IMAGE=$(shell uuidgen))
	${CONTAINER_TOOL} build --target build-env -t ${IMAGE} .
	${CONTAINER_TOOL} run --rm ${IMAGE} /bin/cat /louketo-proxy > bin/louketo-proxy
	${CONTAINER_TOOL} rmi ${IMAGE}
	chmod +x bin/louketo-proxy

.PHONY: container-test docker-test
container-test: docker-test
docker-test:
	@echo "--> Running the container image tests"
	${CONTAINER_TOOL} run --rm -ti -p 3000:3000 \
    -v ${ROOT_DIR}/config.yml:/etc/louketo/config.yml:ro \
    -v ${ROOT_DIR}/tests:/opt/tests:ro \
    ${REGISTRY}/${AUTHOR}/${NAME}:${VERSION} --config /etc/louketo/config.yml

.PHONY: container-release docker-release
container-release: docker-release
docker-release: docker
	@echo "--> Releasing the container image"
	${CONTAINER_TOOL} push ${REGISTRY}/${AUTHOR}/${NAME}:${VERSION}

.PHONY: container docker
container: docker
docker:
	@echo "--> Building the container image"
	${CONTAINER_TOOL} build -t ${REGISTRY}/${AUTHOR}/${NAME}:${VERSION} .

.PHONY: certs
certs:
	@echo "--> Generating the root CA"
	@cfssl gencert -initca tests/ca-csr.json | cfssljson -bare tests/ca
	@echo "--> Generating the Test Certs"
	cfssl gencert \
		-ca=tests/ca.pem \
		-ca-key=tests/ca-key.pem \
		-config=tests/ca-config.json \
		-profile=server \
		tests/proxy-csr.json | cfssljson -bare tests/proxy

.PHONY: clean authors vet lint gofmt verify format bench coverage cover spelling
clean:
	rm -rf ./bin/* 2>/dev/null
	rm -rf ./release/* 2>/dev/null

authors:
	@echo "--> Updating the AUTHORS"
	git log --format='%aN <%aE>' | sort -u > AUTHORS

vet:
	@echo "--> Running go vet $(VETARGS) ."
	@go vet 2>/dev/null ; if [ $$? -eq 3 ]; then \
		go get golang.org/x/tools/cmd/vet; \
	fi
	# This is required due to break of API compatibility in go vet between version 1.11 and 1.12
	@go version | grep '1.11' 2>/dev/null ; if [[ $$? -eq 0 ]]; then \
    go vet $(VETARGS) -structtags *.go; \
	fi
	@go version | grep '1.12' 2>/dev/null ; if [[ $$? -eq 0 ]]; then \
    go vet $(VETARGS) -structtag *.go; \
	fi

lint:
	@echo "--> Running golangci-lint"
	@which golangci-lint 2>/dev/null ; if [ $$? -eq 1 ]; then \
		go get -u github.com/golangci/golangci-lint/cmd/golangci-lint; \
	fi
	@golint .

gofmt:
	@echo "--> Running gofmt check"
	@gofmt -s -l *.go \
	    | grep -q \.go ; if [ $$? -eq 0 ]; then \
            echo "You need to runn the make format, we have file unformatted"; \
            gofmt -s -l *.go; \
            exit 1; \
	    fi

verify:
	@echo "--> Verifying the code"
	golangci-lint run

format:
	@echo "--> Running go fmt"
	@gofmt -s -w *.go

bench:
	@echo "--> Running go bench"
	@go test -bench=. -benchmem

coverage:
	@echo "--> Running go coverage"
	@go test -coverprofile cover.out
	@go tool cover -html=cover.out -o cover.html

cover:
	@echo "--> Running go cover"
	@go test --cover

spelling:
	@echo "--> Checking the spelling"
	@which misspell 2>/dev/null ; if [ $$? -eq 1 ]; then \
		go get -u github.com/client9/misspell/cmd/misspell; \
	fi
	@misspell -error *.go
	@misspell -error *.md

.PHONY: test all changelog
test:
	@echo "--> Running the tests"
	@go test -v
	@$(MAKE) golang
	@$(MAKE) gofmt
	@$(MAKE) spelling
	@$(MAKE) vet
	@$(MAKE) cover

all: test
	echo "--> Performing all tests"
	@${MAKE} verify
	@$(MAKE) bench
	@$(MAKE) coverage

changelog: release
	git log $(shell git tag | tail -n1)..HEAD --no-merges --format=%B > changelog
