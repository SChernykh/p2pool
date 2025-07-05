#!/bin/sh

# Example usage: ./build.sh v4.8.1

cd "$(dirname "$0")"
[ ! -f "p2pool.tar" ] && tar -f p2pool.tar -c ../../cmake -c ../../external -c ../../src -c ../../CMakeLists.txt -c ../../LICENSE -c ../../README.md

docker build --build-arg P2POOL_VERSION=$1 --build-arg BUILD_TIMESTAMP="$(git show --no-patch --format=%ct $1)" -t p2pool_ubuntu_riscv64_build .

docker create --name p2pool_ubuntu_riscv64_build_container p2pool_ubuntu_riscv64_build:latest
docker cp p2pool_ubuntu_riscv64_build_container:/p2pool/build/p2pool-$1-linux-riscv64.tar.gz ../p2pool-$1-linux-riscv64.tar.gz
docker rm p2pool_ubuntu_riscv64_build_container

docker image rm -f p2pool_ubuntu_riscv64_build

rm p2pool.tar
