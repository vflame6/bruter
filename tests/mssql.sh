#!/bin/bash
# MSSQL test
docker run -d --name mssql-bruter -p 127.0.0.1:1433:1433 \
  -e ACCEPT_EULA=Y \
  -e MSSQL_SA_PASSWORD='Bruter12345678!' \
  mcr.microsoft.com/mssql/server:2022-latest

sleep 15  # MSSQL takes a while to start
go run . mssql -u tests/usernames.txt -p tests/passwords.txt -t 127.0.0.1 -D

docker rm -f mssql-bruter
