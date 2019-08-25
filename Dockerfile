FROM python:3.8-rc-alpine3.10 as builder

RUN apk add --update \
    linux-headers \
    tcpdump \
    build-base \
    ebtables

RUN mkdir -p /kube-hunter 
COPY ./requirements.txt /kube-hunter/.
RUN pip install -r /kube-hunter/requirements.txt -t /kube-hunter

COPY . /kube-hunter

FROM python:3.7-alpine3.10

RUN apk add --update \
    tcpdump
RUN apk upgrade 

COPY --from=builder /kube-hunter /kube-hunter

WORKDIR /kube-hunter

ENTRYPOINT ["python",  "kube-hunter.py"]
