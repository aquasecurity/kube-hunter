FROM python:3.8-alpine as builder

RUN apk add --no-cache \
    linux-headers \
    tcpdump \
    build-base \
    ebtables \
    make \
    git && \
    apk upgrade --no-cache

WORKDIR /kube-hunter
COPY setup.py setup.cfg Makefile ./
RUN make deps

COPY . .
RUN make install

ENTRYPOINT ["kube-hunter"]
