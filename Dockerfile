FROM golang:alpine as base

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
RUN LDFLAGS="-s -w -linkmode external -extldflags \"-static\"" &&\
    go build -o /stage/usr/bin/gatekeeper --ldflags "$LDFLAGS" .
RUN upx /stage/usr/bin/gatekeeper

# Build the dist image
FROM scratch
COPY --from=base /stage /
ENV ZONEINFO /zoneinfo.zip
ENTRYPOINT [ "gatekeeper" ]
CMD ["--help"]

