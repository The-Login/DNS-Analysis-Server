FROM python:3.8-alpine

WORKDIR /build

RUN apk --update --no-cache add bind bind-dnssec-tools iptables && pip install scapy && pip install requests
COPY dns_proxy.py /build
COPY named.conf /build
COPY forward.analysis /build
COPY start.sh /build

EXPOSE 53/tcp 53/udp

CMD sh /build/start.sh