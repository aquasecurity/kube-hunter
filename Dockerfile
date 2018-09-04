FROM python:2.7.15-alpine3.8

RUN apk add --update \
    linux-headers \
    build-base \
    tcpdump \
    wireshark

RUN mkdir -p /kube-hunter 
COPY . /kube-hunter
WORKDIR /kube-hunter
RUN pip install -r requirements.txt

ENTRYPOINT ["python",  "kube-hunter.py"]
