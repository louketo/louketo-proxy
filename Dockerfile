FROM alpine:3.7

LABEL Name=keycloak-gatekeeper \
      Release=https://github.com/keycloak/keycloak-gatekeeper \
      Url=https://github.com/keycloak/keycloak-gatekeeper \
      Help=https://github.com/keycloak/keycloak-gatekeeper/issues

RUN apk add --no-cache ca-certificates

ADD templates/ /opt/templates
ADD bin/keycloak-gatekeeper /opt/keycloak-gatekeeper

WORKDIR "/opt"

ENTRYPOINT [ "/opt/keycloak-gatekeeper" ]
