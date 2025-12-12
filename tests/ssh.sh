#!/bin/bash

docker run -d -p 22:2222 -e USER_NAME=admin -e USER_PASSWORD=12345678 -e PASSWORD_ACCESS=true lscr.io/linuxserver/openssh-server:latest

