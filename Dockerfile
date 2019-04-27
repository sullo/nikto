FROM alpine:edge
  
LABEL Author Paul Sec (https://github.com/PaulSec), Nikto User https://github.com/drwetter

RUN apk add --no-cache make perl perl-net-ssleay

COPY . /nikto

RUN addgroup nikto
RUN adduser -G nikto -g "Nikto user"  -s /bin/sh -D nikto

ENV PATH /nikto/program:$PATH

RUN chown -R nikto /nikto

USER nikto
WORKDIR /nikto/program

ENTRYPOINT ["nikto.pl"]
CMD [ "-Help"]
