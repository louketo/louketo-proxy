FROM alpine:3.6
MAINTAINER Rohith <gambol99@gmail.com>

RUN apk add ca-certificates --update

ADD templates/ /opt/templates
ADD bin/keycloak-proxy /opt/keycloak-proxy

WORKDIR "/opt"

ENTRYPOINT [ "/opt/keycloak-proxy" ]
