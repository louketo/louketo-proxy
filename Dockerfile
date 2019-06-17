FROM golang:alpine as base
#
ARG TAG
ARG SHA1
ARG BUILD
#
ENV GITHUB_TAG ${TAG:-"dev"}
ENV GITHUB_SHA1 ${SHA1:-""}
ENV COMPILED ${BUILD:-"0"}
ENV GIT_ORG=github.com/oneconcern
ENV GIT_REPO=${GIT_ORG}/keycloak-gatekeeper
#	Release  = "unreleased - dev"
#	Gitsha   = "no gitsha provided"
#	Compiled = "0"
ENV VERSIONING_FLAGS "-X ${GIT_REPO}/version.Release=${GITHUB_TAG} -X ${GIT_REPO}/version.Gitsha=${GITHUB_SHA1} -X ${GIT_REPO}/version.Compiled=${COMPILED}"

RUN mkdir -p /stage/data /stage/etc/ssl/certs &&\
  apk add --no-cache musl-dev gcc ca-certificates mailcap upx tzdata zip git &&\
  update-ca-certificates &&\
  cp /etc/ssl/certs/ca-certificates.crt /stage/etc/ssl/certs/ca-certificates.crt &&\
  cp /etc/mime.types /stage/etc/mime.types

WORKDIR /usr/share/zoneinfo
RUN zip -r -0 /stage/zoneinfo.zip .

ADD go.mod /gatekeeper/go.mod
ADD go.sum /gatekeeper/go.sum
WORKDIR /gatekeeper
RUN go mod download

ADD . /gatekeeper
RUN LDFLAGS="-s -w -linkmode external -extldflags \"-static\" ${VERSIONING_FLAGS}" &&\
    go build -tags "nostores noforwarding" -o /stage/usr/bin/gatekeeper --ldflags "$LDFLAGS" .
RUN upx /stage/usr/bin/gatekeeper

# Build the dist image
FROM scratch
COPY --from=base /stage /
ENV ZONEINFO /zoneinfo.zip
ENTRYPOINT [ "gatekeeper" ]
CMD ["--help"]

