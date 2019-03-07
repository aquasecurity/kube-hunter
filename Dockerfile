FROM python:3.7.2-alpine3.9

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
