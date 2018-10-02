FROM alpine:edge

LABEL Author Paul Sec (https://github.com/PaulSec)

RUN apk add --no-cache make perl perl-net-ssleay
COPY . /nikto

ENV PATH /nikto/program:$PATH

WORKDIR /nikto/program
ENTRYPOINT ["nikto.pl"]
CMD [ "-Help"]
