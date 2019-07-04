FROM alpine:3.10.0

LABEL version="2.1.6" \
      author="Author Paul Sec (https://github.com/PaulSec), Nikto User https://github.com/drwetter" \
      docker_build="docker build -t sullo/nikto:2.1.6 ." \
      docker_run_basic="docker run --rm sullo/nikto:2.1.6 -h http://www.example.com" \
      docker_run_advanced="docker run --rm -v $(pwd):/tmp sullo/nikto:2.1.6 -h http://www.example.com -o /tmp/out.json"

COPY ["program/", "/nikto"]

ENV  PATH=${PATH}:/nikto

RUN echo 'Selecting packages to Nikto.' \
  && apk update \
  && apk add --no-cache --virtual .build-deps \
     perl \
     perl-net-ssleay \
  && echo 'Cleaning cache from APK.' \
  && rm -rf /var/cache/apk/* \
  && echo 'Creating the nikto group.' \
  && addgroup nikto \
  && echo 'Creating the user nikto.' \
  && adduser -G nikto -g "Nikto user" -s /bin/sh -D nikto \
  && echo 'Changing the ownership.' \
  && chown -R nikto.nikto /nikto \
  && echo 'Creating a random password for root.' \
  && export RANDOM_PASSWORD=`tr -dc A-Za-z0-9 < /dev/urandom | head -c44` \
  && echo "root:$RANDOM_PASSWORD" | chpasswd \
  && unset RANDOM_PASSWORD \
  && echo 'Locking root account.' \
  && passwd -l root \
  && echo 'Finishing image.'

USER nikto

ENTRYPOINT ["nikto.pl"]
