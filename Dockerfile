FROM python:3.7-alpine3.10 as builder

RUN apk add --no-cache \
    linux-headers \
    tcpdump \
    build-base \
    ebtables

WORKDIR /kube-hunter
COPY ./requirements.txt /kube-hunter/.
RUN pip install -r /kube-hunter/requirements.txt -t /kube-hunter

COPY . /kube-hunter

FROM python:3.7-alpine3.10

RUN apk add --no-cache \
    tcpdump
RUN apk upgrade --no-cache 

COPY --from=builder /kube-hunter /kube-hunter

WORKDIR /kube-hunter

ENTRYPOINT ["python",  "kube-hunter.py"]
