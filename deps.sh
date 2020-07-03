#!/bin/bash
NGINX_VERSION="1.18.0"
cd libs
wget https://nginx.org/download/nginx-$NGINX_VERSION.tar.gz
tar -xzvf nginx-$NGINX_VERSION.tar.gz
rm nginx-$NGINX_VERSION.tar.gz
cd ../..
