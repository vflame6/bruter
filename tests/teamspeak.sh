#!/bin/bash
# TeamSpeak 3 ServerQuery test
docker run -d --name ts3-bruter -p 127.0.0.1:10011:10011 \
  -e TS3SERVER_LICENSE=accept \
  teamspeak:latest

sleep 10  # TeamSpeak takes a while to initialize
go run . teamspeak -u tests/usernames.txt -p tests/passwords.txt -t 127.0.0.1 -D

docker rm -f ts3-bruter
