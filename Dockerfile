FROM alpine:3.5
MAINTAINER Rohith <gambol99@gmail.com>

RUN apk update && \
    apk add ca-certificates

ADD templates/ /opt/templates
ADD bin/keycloak-proxy /opt/keycloak-proxy

WORKDIR "/opt"

ENTRYPOINT [ "/opt/keycloak-proxy" ]
