#!/bin/bash
# LDAP test using OpenLDAP
docker run -d --name openldap-bruter -p 127.0.0.1:389:389 \
  -e LDAP_ADMIN_USERNAME=admin \
  -e LDAP_ADMIN_PASSWORD=12345678 \
  -e LDAP_ROOT=dc=example,dc=org \
  bitnami/openldap:latest

sleep 5
# LDAP bind DN format: cn=admin,dc=example,dc=org
go run . ldap -u tests/usernames.txt -p tests/passwords.txt -t 127.0.0.1 -D

docker rm -f openldap-bruter
