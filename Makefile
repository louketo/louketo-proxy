
NAME=oidc-proxy
AUTHOR=gambol99
HARDWARE=$(shell uname -m)
GOVERSION=1.5.3
GIT_COMMIT=$(shell git log --pretty=format:'%h' -n 1)
ROOT_DIR=${PWD}
VERSION=$(shell awk '/version.*=/ { print $$3 }' doc.go | sed 's/"//g')
DEPS=$(shell go list -f '{{range .TestImports}}{{.}} {{end}}' ./...)
PACKAGES=$(shell go list ./...)
VETARGS?=-asmdecl -atomic -bool -buildtags -copylocks -methods -nilfunc -printf -rangeloops -shift -structtags -unsafeptr

.PHONY: test authors changelog build docker static release lint cover vet

default: build

golang:
	@echo "--> Go Version"
	@go version

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
	sudo docker run --rm -v ${ROOT_DIR}:/go/src/github.com/gambol99/oidc-proxy \
		-w /go/src/github.com/gambol99/oidc-proxy -e GOOS=linux golang:${GOVERSION} make static

docker: static
	@echo "--> Building the docker image"
	sudo docker build -t docker.io/${AUTHOR}/${NAME}:${VERSION} .

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
	@godep go test -v
	@$(MAKE) gofmt
	@$(MAKE) vet
	@$(MAKE) cover

changelog: release
	git log $(shell git tag | tail -n1)..HEAD --no-merges --format=%B > changelog
