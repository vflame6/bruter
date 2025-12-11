#!/usr/bin/env bash

export PASSWORD="password"

CONTAINER_ID=$(docker run -d --rm -p 127.0.0.1:2379:2379 \
  --name etcd quay.io/coreos/etcd:v3.5.21 etcd \
  --initial-advertise-peer-urls http://0.0.0.0:2380 --listen-peer-urls http://0.0.0.0:2380 \
  --advertise-client-urls http://0.0.0.0:2379 --listen-client-urls http://0.0.0.0:2379 \
  --initial-cluster node1=http://0.0.0.0:2380 \
  --name node1)

sleep 5
docker run -it --net=host -e ETCDCTL_API=3 quay.io/coreos/etcd:v3.5.21 etcdctl --endpoints http://0.0.0.0:2379 user add "root:${PASSWORD}"
docker run -it --net=host -e ETCDCTL_API=3 quay.io/coreos/etcd:v3.5.21 etcdctl --endpoints http://0.0.0.0:2379 auth enable --user "root:${PASSWORD}"
