#!/bin/sh
cd "$(dirname "$0")"
docker build -t p2pool_build_ubuntu .
