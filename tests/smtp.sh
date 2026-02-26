#!/bin/bash
# SMTP test using GreenMail (supports SMTP on 3025, IMAP on 3143, POP3 on 3110)
docker run -d --name greenmail -p 127.0.0.1:3025:3025 -p 127.0.0.1:3143:3143 -p 127.0.0.1:3110:3110 \
  -e GREENMAIL_OPTS='-Dgreenmail.setup.test.all -Dgreenmail.users=testuser:12345678' \
  greenmail/standalone:2.1.2

sleep 5
go run . smtp -u tests/usernames.txt -p tests/passwords.txt -t 127.0.0.1:3025 -D

docker rm -f greenmail
