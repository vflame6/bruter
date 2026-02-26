#!/bin/bash
# RTSP test using mediamtx (formerly rtsp-simple-server)
docker run -d --name rtsp-bruter -p 127.0.0.1:8554:8554 \
  -e MTX_PATHS_ALL_READUSER=admin \
  -e MTX_PATHS_ALL_READPASS=12345678 \
  bluenviron/mediamtx:latest

sleep 3
go run . rtsp -u tests/usernames.txt -p tests/passwords.txt -t 127.0.0.1:8554 -D

docker rm -f rtsp-bruter
