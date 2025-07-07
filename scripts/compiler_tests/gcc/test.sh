#!/bin/sh

cd /p2pool
git fetch --jobs=$(nproc)
git checkout $1
git submodule update --recursive --jobs $(nproc)

export COMPILER="-DCMAKE_C_COMPILER=/usr/local/gcc-$2/bin/gcc -DCMAKE_CXX_COMPILER=/usr/local/gcc-$2/bin/g++ -DCMAKE_AR=/usr/local/gcc-$2/bin/gcc-ar -DCMAKE_RANLIB=/usr/local/gcc-$2/bin/gcc-ranlib"

./test2.sh

tar -czvf /p2pool/logs.tar.gz /p2pool/output.log
