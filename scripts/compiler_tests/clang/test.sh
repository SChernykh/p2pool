#!/bin/sh

cd /p2pool
git fetch --jobs=$(nproc)
git checkout $1
git submodule update --recursive --jobs $(nproc)

export COMPILER="-DCMAKE_C_COMPILER=clang-$2 -DCMAKE_CXX_COMPILER=clang++-$2"

./test2.sh

tar -czvf /p2pool/logs.tar.gz /p2pool/output.log
