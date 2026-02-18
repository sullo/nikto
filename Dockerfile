FROM alpine:3.21.3

LABEL version="2.5.0" \
      author="Author Paul Sec (https://github.com/PaulSec), Nikto User https://github.com/drwetter" \
      docker_build="docker build -t sullo/nikto:2.5.0 ." \
      docker_run_basic="docker run --rm sullo/nikto:2.5.0 -h http://www.example.com" \
      docker_run_advanced="docker run --rm -v $(pwd):/tmp sullo/nikto:2.5.0 -h http://www.example.com -o /tmp/out.json"

RUN echo 'Installing packages for Nikto.' && \
    apk add --no-cache \
      perl \
      perl-net-ssleay \
      perl-json \
      perl-io-socket-ssl \
      perl-xml-writer \
      perl-mime-base64 \
      perl-xml-libxml

RUN echo 'Creating the nikto group.' && \
  addgroup -S nikto && \
  echo 'Creating the nikto user.' && \
  adduser -S -G nikto -g "Nikto user" -s /bin/sh nikto

ENV  PATH=${PATH}:/opt/nikto
USER nikto

COPY --chown=nikto:nikto ["program/", "/opt/nikto"]
ENTRYPOINT ["/opt/nikto/nikto.pl"]
