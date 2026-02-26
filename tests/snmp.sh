#!/bin/bash
# SNMP test using snmpd
docker run -d --name snmpd-bruter -p 127.0.0.1:161:161/udp \
  polinux/snmpd

sleep 3
# SNMP uses community strings as passwords (no username)
go run . snmp -p tests/passwords.txt -t 127.0.0.1 -D

docker rm -f snmpd-bruter
