#!/bin/bash
# Asterisk Manager Interface test
docker run -d --name asterisk-bruter -p 127.0.0.1:5038:5038 \
  andrius/asterisk:latest

sleep 5
go run . asterisk -u tests/usernames.txt -p tests/passwords.txt -t 127.0.0.1 -D

docker rm -f asterisk-bruter
