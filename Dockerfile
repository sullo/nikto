FROM alpine:3.15

LABEL version="2.1.6" \
      author="Author Paul Sec (https://github.com/PaulSec), Nikto User https://github.com/drwetter" \
      docker_build="docker build -t sullo/nikto:2.1.6 ." \
      docker_run_basic="docker run --rm sullo/nikto:2.1.6 -h http://www.example.com" \
      docker_run_advanced="docker run --rm -v $(pwd):/tmp sullo/nikto:2.1.6 -h http://www.example.com -o /tmp/out.json"

COPY ["program/", "/nikto"]

ENV  PATH=${PATH}:/nikto

RUN echo 'Installing packages for Nikto.' \
  && apk add --update --no-cache --virtual .build-deps \
     perl \
     perl-net-ssleay \
  && echo 'Creating the nikto group.' \
  && addgroup nikto \
  && echo 'Creating the nikto user.' \
  && adduser -G nikto -g "Nikto user" -s /bin/sh -D nikto \
  && echo 'Changing the ownership.' \
  && chown -R nikto.nikto /nikto \
  && echo 'Finishing image.'

USER nikto

ENTRYPOINT ["nikto.pl"]
