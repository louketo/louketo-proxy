
NAME=keycloak-proxy
AUTHOR=gambol99
REGISTRY=docker.io
GOVERSION=1.6.0
SUDO=sudo
ROOT_DIR=${PWD}
HARDWARE=$(shell uname -m)
GIT_SHA=$(shell git --no-pager describe --tags --always --dirty)
VERSION=$(shell awk '/version.*=/ { print $$3 }' doc.go | sed 's/"//g')
DEPS=$(shell go list -f '{{range .TestImports}}{{.}} {{end}}' ./...)
PACKAGES=$(shell go list ./...)
VETARGS?=-asmdecl -atomic -bool -buildtags -copylocks -methods -nilfunc -printf -rangeloops -shift -structtags -unsafeptr

.PHONY: test authors changelog build docker static release lint cover vet

default: build

golang:
	@echo "--> Go Version"
	@go version

version:
	@sed -i "s/const gitSHA =.*/const gitSHA = \"${GIT_SHA}\"/" doc.go

build:
	@echo "--> Compiling the project"
	mkdir -p bin
	godep go build -o bin/${NAME}

static: golang deps
	@echo "--> Compiling the static binary"
	mkdir -p bin
	CGO_ENABLED=0 GOOS=linux godep go build -a -tags netgo -ldflags '-w' -o bin/${NAME}

docker-build:
	@echo "--> Compiling the project"
	${SUDO} docker run --rm -v ${ROOT_DIR}:/go/src/github.com/gambol99/keycloak-proxy \
		-w /go/src/github.com/gambol99/keycloak-proxy -e GOOS=linux golang:${GOVERSION} make static

docker:
	@echo "--> Building the docker image"
	${SUDO} docker build -t ${REGISTRY}/${AUTHOR}/${NAME}:${VERSION} .

docker-push:
	@echo "--> Pushing the docker images to the registry"
	${SUDO} docker push ${REGISTRY}/${AUTHOR}/${NAME}:${VERSION}

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

deps:
	@echo "--> Installing build dependencies"
	@go get github.com/tools/godep

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

format:
	@echo "--> Running go fmt"
	@gofmt -s -w *.go

coverage:
	@echo "--> Running go coverage"
	@godep go test -coverprofile cover.out
	@godep go tool cover -html=cover.out -o cover.html

cover:
	@echo "--> Running go cover"
	@godep go test --cover

test: deps
	@echo "--> Running the tests"
	@export GIN_MODE=release
	@godep go test -v
	@$(MAKE) gofmt
	@$(MAKE) vet
	@$(MAKE) cover

changelog: release
	git log $(shell git tag | tail -n1)..HEAD --no-merges --format=%B > changelog
