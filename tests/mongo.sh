#!/bin/bash

docker run -d --name mongo-default -p 127.0.0.1:27017:27017 mongo
docker run -d --name mongo-password -p 127.0.0.1:10000:27017 -e MONGO_INITDB_ROOT_USERNAME=admin -e MONGO_INITDB_ROOT_PASSWORD=password mongo
