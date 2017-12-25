FROM golang:1.9 as build
RUN  go get -d github.com/gambol99/keycloak-proxy \
     && cd /go/src/github.com/gambol99/keycloak-proxy \
     && make static

FROM ubuntu as certs
RUN  apt-get update && apt-get install -y ca-certificates

FROM scratch
COPY --from=build /go/src/github.com/gambol99/keycloak-proxy/bin/keycloak-proxy /opt/keycloak-proxy
COPY --from=certs /etc/ssl/certs /etc/ssl/certs

LABEL Name=keycloak-proxy \
      Maintainer="Rohith Jayawardene <gambol99@gmail.com>" \
      Release=https://github.com/gambol99/keycloak-proxy \
      Url=https://github.com/gambol99/keycloak-proxy \
      Help=https://github.com/gambol99/keycloak-proxy/issues

ADD templates/ /opt/templates

WORKDIR /opt

CMD [ "/opt/keycloak-proxy" ]
