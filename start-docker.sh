#!/bin/bash
docker run -it \
  --name evilginx \
  -p 127.0.0.1:8080:80 \
  -p 127.0.0.1:8443:443 \
  -p 127.0.0.1:2030:2030 \
  -p 127.0.0.1:3333:3333 \
  -v /root/.evilginx:/root/.evilginx \
  evilginx:latest