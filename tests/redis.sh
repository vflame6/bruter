#!/bin/bash

docker run -d --name redis-default -p 127.0.0.1:6379:6379 redis:latest
docker run -d --name redis-password -p 127.0.0.1:10000:6379 redis redis-server --requirepass "12345678"
