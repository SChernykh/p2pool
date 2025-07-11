#!/bin/sh

# Example usage: ./build.sh v4.8.1

cd "$(dirname "$0")"

docker build --build-arg P2POOL_VERSION=$1 -t p2pool_freebsd_aarch64_build_$1 .

docker create --name p2pool_freebsd_aarch64_build_$1_container p2pool_freebsd_aarch64_build_$1:latest
docker cp p2pool_freebsd_aarch64_build_$1_container:/p2pool/build/p2pool-$1-freebsd-aarch64.tar.gz ../p2pool-$1-freebsd-aarch64.tar.gz
docker rm p2pool_freebsd_aarch64_build_$1_container

docker image rm -f p2pool_freebsd_aarch64_build_$1
