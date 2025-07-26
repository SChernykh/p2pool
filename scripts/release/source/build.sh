#!/bin/sh

# Example usage: ./build.sh v4.8.1

cd "$(dirname "$0")"

docker build --cpuset-cpus $2 --build-arg P2POOL_VERSION=$1 -t p2pool_source_build_$1 .

docker create --name p2pool_source_build_$1_container p2pool_source_build_$1:latest
docker cp p2pool_source_build_$1_container:/p2pool_source-$1.tar.xz ../p2pool_source-$1.tar.xz
docker rm p2pool_source_build_$1_container

docker image rm -f p2pool_source_build_$1
