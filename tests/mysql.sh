#!/bin/bash
# MySQL test
docker run -d --name mysql-bruter -p 127.0.0.1:3306:3306 \
  -e MYSQL_ROOT_PASSWORD=12345678 \
  mysql:8

sleep 15  # MySQL takes longer to initialize
go run . mysql -u tests/usernames.txt -p tests/passwords.txt -t 127.0.0.1 -D

docker rm -f mysql-bruter
