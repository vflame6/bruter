#!/bin/bash
# XMPP test using Prosody
docker run -d --name prosody-bruter -p 127.0.0.1:5222:5222 \
  prosody/prosody:latest

sleep 5
# Register a test user (may need prosodyctl inside container)
docker exec prosody-bruter prosodyctl register admin localhost 12345678 2>/dev/null

go run . xmpp -u tests/usernames.txt -p tests/passwords.txt -t 127.0.0.1 -D

docker rm -f prosody-bruter
