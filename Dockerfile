FROM alpine:3.19

LABEL version="2.5.0" \
      author="Author Paul Sec (https://github.com/PaulSec), Nikto User https://github.com/drwetter" \
      docker_build="docker build -t sullo/nikto:2.5.0 ." \
      docker_run_basic="docker run --rm sullo/nikto:2.5.0 -h http://www.example.com" \
      docker_run_advanced="docker run --rm -v $(pwd):/tmp sullo/nikto:2.5.0 -h http://www.example.com -o /tmp/out.json"

RUN echo 'Installing packages for Nikto.'
RUN apk add --update --no-cache --virtual .build-deps \
     perl \
     perl-net-ssleay

RUN echo 'Creating the nikto group.' \
  && addgroup nikto \
  && echo 'Creating the nikto user.' \
  && adduser -G nikto -g "Nikto user" -s /bin/sh -HD nikto

ENV  PATH=${PATH}:/opt/nikto
USER nikto

COPY --chown=nikto:nikto ["program/", "/opt/nikto"]
ENTRYPOINT ["nikto.pl"]
