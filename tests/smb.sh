#!/bin/bash
# SMB test using Samba
docker run -d --name samba-bruter -p 127.0.0.1:445:445 \
  -e USER=admin -e PASS=12345678 \
  dperson/samba -u "admin;12345678" -s "share;/share;yes;no;no;admin"

sleep 5
go run . smb -u tests/usernames.txt -p tests/passwords.txt -t 127.0.0.1 -D

docker rm -f samba-bruter
