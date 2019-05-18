FROM python:3.7.3-alpine3.9 as builder

RUN apk add --update \
    linux-headers \
    wireshark \
    tcp-dump \
    build-base

RUN mkdir -p /kube-hunter 
COPY ./requirements.txt /kube-hunter/.
RUN pip install -r /kube-hunter/requirements.txt -t /kube-hunter

COPY . /kube-hunter

FROM python:3.7.3-alpine3.9

RUN apk add --update \
    linux-headers \
    wireshark \
    tcpdump 

COPY --from=builder /kube-hunter /kube-hunter
WORKDIR /kube-hunter

ENTRYPOINT ["python",  "kube-hunter.py"]
