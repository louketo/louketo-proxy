FROM alpine:3.3
MAINTAINER Rohith <gambol99@gmail.com>

RUN apk update && \
    apk add ca-certificates && \
    adduser -S proxy && \
    addgroup -S proxy

ADD templates/ opt/templates
ADD bin/keycloak-proxy /opt/keycloak-proxy
RUN chmod +x /opt/keycloak-proxy

WORKDIR "/opt"

USER proxy

ENTRYPOINT [ "/opt/keycloak-proxy" ]
