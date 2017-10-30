FROM alpine:3.6
MAINTAINER Rohith Jayawardene <gambol99@gmail.com>
LABEL Name=keycloak-proxy \
      Release=https://github.com/gambol99/keycloak-proxy \
      Url=https://github.com/gambol99/keycloak-proxy \
      Help=https://github.com/gambol99/keycloak-proxy/issues

RUN apk add --no-cache ca-certificates

ADD templates/ /opt/templates
ADD bin/keycloak-proxy /opt/keycloak-proxy

RUN useradd -mUrd /kcproxy kcproxy \
    && chown -R kcproxy:kcproxy /opt

USER kcproxy

WORKDIR "/opt"

ENTRYPOINT [ "/opt/keycloak-proxy" ]
