#!/bin/sh

# Example usage: ./build.sh v4.8.1

cd "$(dirname "$0")"

docker build --build-arg P2POOL_VERSION=$1 --build-arg BUILD_TIMESTAMP="$(git show --no-patch --format=%ct $1)" -t p2pool_source_build .

docker create --name p2pool_source_build_container p2pool_source_build:latest
docker cp p2pool_source_build_container:/root/p2pool_source-$1.tar.xz ../p2pool_source-$1.tar.xz
docker rm p2pool_source_build_container

docker image rm -f p2pool_source_build
