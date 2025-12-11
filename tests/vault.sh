#!/usr/bin/env bash

export PASSWORD="password"

docker run -d --rm -p 127.0.0.1:8200:8200 --name vault -e VAULT_DEV_ROOT_TOKEN_ID=root hashicorp/vault:latest

sleep 10

docker run -it --net=host -e VAULT_ADDR=http://0.0.0.0:8200 -e VAULT_TOKEN=root hashicorp/vault auth enable userpass
docker run -it --net=host -e VAULT_ADDR=http://0.0.0.0:8200 -e VAULT_TOKEN=root hashicorp/vault write auth/userpass/users/root password=${PASSWORD} policies=root
docker run -it --net=host -e VAULT_ADDR=http://0.0.0.0:8200 -e VAULT_TOKEN=root hashicorp/vault write auth/userpass/users/admin password=${PASSWORD} policies=admins
docker run -it --net=host -e VAULT_ADDR=http://0.0.0.0:8200 -e VAULT_TOKEN=root hashicorp/vault auth tune -user-lockout-disable=true userpass/
