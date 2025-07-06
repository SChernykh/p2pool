#!/bin/sh

cd /p2pool
git fetch --jobs=$(nproc)
git checkout $1
git submodule update --recursive --jobs $(nproc)

COMPILER="-DCMAKE_C_COMPILER=clang-$2 -DCMAKE_CXX_COMPILER=clang++-$2"

cd /p2pool
mkdir build && cd build

cmake .. -DCMAKE_BUILD_TYPE=Release $COMPILER 1>> /p2pool/output.log 2>&1
make -j$(nproc) p2pool 1>> /p2pool/output.log 2>&1
./p2pool --test 1>> /p2pool/output.log 2>&1

cd ../tests
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release $COMPILER 1>> /p2pool/output.log 2>&1
make -j$(nproc) p2pool_tests 1>> /p2pool/output.log 2>&1
gunzip *.gz
./p2pool_tests 1>> /p2pool/output.log 2>&1

tar -czvf /p2pool/logs.tar.gz /p2pool/output.log
