#!/bin/sh
set -eu
cd "$(dirname "$0")"
docker build -t p2pool_build_ubuntu .
