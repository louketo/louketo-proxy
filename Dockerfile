FROM golang:1.10.2 as builder

WORKDIR /go/src/github.com/keycloak/keycloak-gatekeeper
COPY . ./

RUN go get -u github.com/golang/dep/cmd/dep \
    && dep ensure \
    && go test

RUN CGO_ENABLED=0 go build -a -ldflags '-s' -installsuffix cgo -o bin/keycloak-gatekeeper .

FROM alpine:3.7

LABEL Name=keycloak-gatekeeper \
      Release=https://github.com/keycloak/keycloak-gatekeeper \
      Url=https://github.com/keycloak/keycloak-gatekeeper \
      Help=https://github.com/keycloak/keycloak-gatekeeper/issues

RUN apk add --no-cache ca-certificates

ADD templates/ /opt/templates

COPY --from=builder /go/src/github.com/keycloak/keycloak-gatekeeper/bin/keycloak-gatekeeper /opt/keycloak-gatekeeper

WORKDIR "/opt"

ENTRYPOINT ["/opt/keycloak-gatekeeper"]
