FROM python:2.7.15-jessie

WORKDIR /usr/src/kube-hunter

RUN apt-get update && apt-get install -y tcpdump

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENTRYPOINT ["python", "kube-hunter.py"]