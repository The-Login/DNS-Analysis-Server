#!/bin/sh

sed -i "s/domain.example/$NS_DOMAIN/g" /build/*
sed -i "s/203.0.113.37/$NS_IP/g" /build/*

cp /build/named.conf /etc/bind/named.conf
cp /build/forward.analysis /etc/bind/forward.analysis

iptables -I OUTPUT -p icmp --icmp-type destination-unreachable -j DROP

python3 /build/dns_proxy.py &

named -c /etc/bind/named.conf -g -u named &> /dev/null
