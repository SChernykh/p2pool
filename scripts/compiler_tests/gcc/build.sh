#!/bin/sh

# Example usage: ./build.sh v4.8.1 15

cd "$(dirname "$0")"

docker build --build-arg P2POOL_VERSION=$1 --build-arg GCC_VERSION=$2 -t p2pool_compiler_test_gcc_$2 .

docker create --name p2pool_compiler_test_gcc_$2_container p2pool_compiler_test_gcc_$2:latest
docker cp p2pool_compiler_test_gcc_$2_container:/p2pool/logs.tar.gz gcc_$2_logs.tar.gz
docker rm p2pool_compiler_test_gcc_$2_container

docker image rm -f p2pool_compiler_test_gcc_$2
