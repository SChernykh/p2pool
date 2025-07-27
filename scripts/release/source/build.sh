#!/bin/sh

# Example usage: ./build.sh v4.9

cd "$(dirname "$0")"

if [ "$2" ]; then
	cpu_set="--cpuset-cpus $2"
else
	cpu_set=""
fi

docker build $cpu_set --build-arg P2POOL_VERSION=$1 -t p2pool_source_build_$1 .

docker create --name p2pool_source_build_$1_container p2pool_source_build_$1:latest
docker cp p2pool_source_build_$1_container:/p2pool_source-$1.tar.xz ../p2pool_source-$1.tar.xz
docker rm p2pool_source_build_$1_container

docker image rm -f p2pool_source_build_$1
