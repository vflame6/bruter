#!/bin/bash
# IRC server password test using InspIRCd
# Note: IRC server password is set via config, not user auth
docker run -d --name inspircd-bruter -p 127.0.0.1:6667:6667 \
  inspircd/inspircd-docker:latest

sleep 3
go run . irc -p tests/passwords.txt -t 127.0.0.1 -D

docker rm -f inspircd-bruter
