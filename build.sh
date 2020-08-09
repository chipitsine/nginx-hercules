#!/bin/bash
NGINX_VERSION="1.18.0"
cd libs/nginx-$NGINX_VERSION
./configure --with-compat --with-debug --add-dynamic-module=../../src
make modules
cd ../..