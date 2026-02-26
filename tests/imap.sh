#!/bin/bash
# IMAP test using GreenMail (port 3143)
docker run -d --name greenmail-imap -p 127.0.0.1:3143:3143 \
  -e GREENMAIL_OPTS='-Dgreenmail.setup.test.all -Dgreenmail.users=testuser:12345678' \
  greenmail/standalone:2.1.2

sleep 5
go run . imap -u tests/usernames.txt -p tests/passwords.txt -t 127.0.0.1:3143 -D

docker rm -f greenmail-imap
