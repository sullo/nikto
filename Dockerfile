FROM alpine:edge

LABEL Author Paul Sec (https://github.com/PaulSec)

RUN apk add --no-cache git make perl
RUN git clone https://github.com/sullo/nikto

ENV PATH /nikto/program:$PATH

WORKDIR /nikto/program
CMD ["nikto.pl"]