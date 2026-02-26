#!/bin/bash
# VNC test
docker run -d --name vnc-bruter -p 127.0.0.1:5900:5900 \
  -e VNC_PW=12345678 \
  consol/rocky-xfce-vnc:latest

sleep 5
# VNC uses password-only auth (no username)
go run . vnc -p tests/passwords.txt -t 127.0.0.1 -D

docker rm -f vnc-bruter
