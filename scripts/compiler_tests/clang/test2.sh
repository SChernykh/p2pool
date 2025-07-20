#!/bin/sh
set -e

cd /p2pool
mkdir build && cd build

cmake .. -DCMAKE_BUILD_TYPE=Release $COMPILER 1>> /p2pool/output.log 2>&1
make -j$(nproc) p2pool 1>> /p2pool/output.log 2>&1

./p2pool --test 1>> /p2pool/output.log 2>&1

make -j$(nproc) randomx-tests 1>> /p2pool/output.log 2>&1
external/src/RandomX/randomx-tests 1>> /p2pool/output.log 2>&1

cd ../tests
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release $COMPILER 1>> /p2pool/output.log 2>&1
make -j$(nproc) p2pool_tests 1>> /p2pool/output.log 2>&1
unxz *.xz

./p2pool_tests 1>> /p2pool/output.log 2>&1
