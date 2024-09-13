FROM alpine:3.19

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
