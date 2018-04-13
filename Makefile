NAME=keycloak-proxy
AUTHOR=gambol99
AUTHOR_EMAIL=gambol99@gmail.com
REGISTRY=quay.io
GOVERSION ?= 1.10
ROOT_DIR=${PWD}
HARDWARE=$(shell uname -m)
GIT_SHA=$(shell git --no-pager describe --always --dirty)
BUILD_TIME=$(shell date '+%s')
VERSION ?= $(shell awk '/release.*=/ { print $$3 }' doc.go | sed 's/"//g')
DEPS=$(shell go list -f '{{range .TestImports}}{{.}} {{end}}' ./...)
PACKAGES=$(shell go list ./...)
LFLAGS ?= -X main.gitsha=${GIT_SHA} -X main.compiled=${BUILD_TIME}
VETARGS ?= -asmdecl -atomic -bool -buildtags -copylocks -methods -nilfunc -printf -rangeloops -shift -structtags -unsafeptr

.PHONY: test authors changelog build docker static release lint cover vet glide-install

default: build

golang:
	@echo "--> Go Version"
	@go version

build: golang
	@echo "--> Compiling the project"
	@mkdir -p bin
	go build -ldflags "${LFLAGS}" -o bin/${NAME}

static: golang deps
	@echo "--> Compiling the static binary"
	@mkdir -p bin
	CGO_ENABLED=0 GOOS=linux go build -a -tags netgo -ldflags "-w ${LFLAGS}" -o bin/${NAME}

docker-build:
	@echo "--> Compiling the project"
	docker run --rm \
		-v ${ROOT_DIR}:/go/src/github.com/${AUTHOR}/${NAME} \
		-w /go/src/github.com/${AUTHOR}/${NAME} \
		-e GOOS=linux golang:${GOVERSION} \
		make static

docker-test:
	@echo "--> Running the docker test"
	docker run --rm -ti -p 3000:3000 \
    -v ${ROOT_DIR}/config.yml:/etc/keycloak/config.yml:ro \
    -v ${ROOT_DIR}/tests:/opt/tests:ro \
    ${REGISTRY}/${AUTHOR}/${NAME}:${VERSION} --config /etc/keycloak/config.yml

docker-release:
	@echo "--> Building a release image"
	@$(MAKE) static
	@$(MAKE) docker
	@docker push ${REGISTRY}/${AUTHOR}/${NAME}:${VERSION}

docker:
	@echo "--> Building the docker image"
	docker build -t ${REGISTRY}/${AUTHOR}/${NAME}:${VERSION} .

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

release: static
	mkdir -p release
	gzip -c bin/${NAME} > release/${NAME}_${VERSION}_linux_${HARDWARE}.gz
	rm -f release/${NAME}

clean:
	rm -rf ./bin 2>/dev/null
	rm -rf ./release 2>/dev/null

authors:
	@echo "--> Updating the AUTHORS"
	git log --format='%aN <%aE>' | sort -u > AUTHORS

glide-install:
	@echo "--> Installing dependencies"
	@glide install

deps:
	@echo "--> Installing build dependencies"
	@go get github.com/Masterminds/glide
	@$(MAKE) glide-install

vet:
	@echo "--> Running go vet $(VETARGS) ."
	@go tool vet 2>/dev/null ; if [ $$? -eq 3 ]; then \
		go get golang.org/x/tools/cmd/vet; \
	fi
	@go tool vet $(VETARGS) *.go

lint:
	@echo "--> Running golint"
	@which golint 2>/dev/null ; if [ $$? -eq 1 ]; then \
		go get -u github.com/golang/lint/golint; \
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
	gometalinter --disable=errcheck --disable=gocyclo --disable=gas --disable=aligncheck --errors

format:
	@echo "--> Running go fmt"
	@gofmt -s -w *.go

bench:
	@echo "--> Running go bench"
	@go test -bench=.

coverage:
	@echo "--> Running go coverage"
	@go test -coverprofile cover.out
	@go tool cover -html=cover.out -o cover.html

cover:
	@echo "--> Running go cover"
	@go test --cover

spelling:
	@echo "--> Chekcing the spelling"
	@which misspell 2>/dev/null ; if [ $$? -eq 1 ]; then \
		go get -u github.com/client9/misspell/cmd/misspell; \
	fi
	@misspell -error *.go
	@misspell -error *.md

test:
	@echo "--> Running the tests"
	@if [ ! -d "vendor" ]; then \
		make glide-install; \
  fi
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
