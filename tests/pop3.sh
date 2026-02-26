#!/bin/bash
# POP3 test using GreenMail (port 3110)
docker run -d --name greenmail-pop3 -p 127.0.0.1:3110:3110 \
  -e GREENMAIL_OPTS='-Dgreenmail.setup.test.all -Dgreenmail.users=testuser:12345678' \
  greenmail/standalone:2.1.2

sleep 5
go run . pop3 -u tests/usernames.txt -p tests/passwords.txt -t 127.0.0.1:3110 -D

docker rm -f greenmail-pop3
