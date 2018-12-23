FROM python:2.7.15-alpine3.8

RUN apk add --update \
    linux-headers \
    build-base \
    tcpdump \
    wireshark

RUN mkdir -p /kube-hunter 
COPY ./requirements.txt /kube-hunter/.
RUN pip install -r /kube-hunter/requirements.txt

COPY . /kube-hunter
WORKDIR /kube-hunter

ENTRYPOINT ["python",  "kube-hunter.py"]
