#!/bin/bash

docker run --name postgres-password -e POSTGRES_PASSWORD=12345678 -p 5432:5432 -d postgres
