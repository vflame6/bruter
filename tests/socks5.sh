#!/bin/bash
# SOCKS5 test with username/password auth
docker run -d --name socks5-bruter -p 127.0.0.1:1080:1080 \
  -e PROXY_USER=admin -e PROXY_PASSWORD=12345678 \
  serjs/go-socks5-proxy

sleep 3
go run . socks5 -u tests/usernames.txt -p tests/passwords.txt -t 127.0.0.1 -D

docker rm -f socks5-bruter
