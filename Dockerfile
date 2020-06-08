#
# Builder image
#

FROM golang:1.14.4 AS build-env
ARG SOURCE=*

ADD $SOURCE /src/
WORKDIR /src/

# Unpack any tars, then try to execute a Makefile, but if the SOURCE url is
# just a tar of binaries, then there probably won't be one. Using multiple RUN
# commands to ensure any errors are caught.
RUN find . -name '*.tar.gz' -type f | xargs -rn1 tar -xzf
RUN if [ -f Makefile ]; then make; fi
RUN cp "$(find . -name 'louketo-proxy' -type f -print -quit)" /louketo-proxy

#
# Actual image
#

FROM registry.access.redhat.com/ubi8/ubi-minimal:8.2

LABEL Name=louketo-proxy \
      Release=https://github.com/louketo/louketo-proxy \
      Url=https://github.com/louketo/louketo-proxy \
      Help=https://github.com/louketo/louketo-proxy/issues

WORKDIR "/opt/louketo"

RUN echo "louketo:x:1000:louketo" >> /etc/group && \
    echo "louketo:x:1000:1000:louketo user:/opt/louketo:/sbin/nologin" >> /etc/passwd && \
    chown -R louketo:louketo /opt/louketo && \
    chmod -R g+rw /opt/louketo

COPY templates ./templates
COPY --from=build-env /louketo-proxy ./
RUN chmod +x louketo-proxy

USER 1000
ENTRYPOINT [ "/opt/louketo/louketo-proxy" ]
