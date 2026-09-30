#!/bin/sh
set -e

echo "Installing prerequisites"

export DEBIAN_FRONTEND=noninteractive

apt-get update && apt-get upgrade -yq --no-install-recommends
apt-get install -yq --no-install-recommends ca-certificates curl bzip2 flex lsb-release wget software-properties-common gnupg xz-utils git gcc g++ cmake make libuv1-dev libzmq3-dev libsodium-dev libpgm-dev libnorm-dev libgss-dev libcurl4-openssl-dev libidn2-0-dev

echo "Installing GCC 8.5.0"

cd /root

git clone --depth 1 --branch releases/gcc-8.5.0 --jobs $(nproc) git://gcc.gnu.org/git/gcc.git gcc-8

cd gcc-8
contrib/download_prerequisites

mkdir build && cd build
../configure --enable-languages=c,c++ --disable-multilib --disable-bootstrap --prefix=/usr/local/gcc-8
make -j$(nproc)
make install

echo "Installing GCC 16.2.0"

cd /root

git clone --depth 1 --branch releases/gcc-16.2.0 --jobs $(nproc) git://gcc.gnu.org/git/gcc.git gcc-16

cd gcc-16
contrib/download_prerequisites

mkdir build && cd build
../configure --enable-languages=c,c++ --disable-multilib --disable-bootstrap --prefix=/usr/local/gcc-16
make -j$(nproc)
make install

echo "Installing clang"

cd /root

curl -L -O https://apt.llvm.org/llvm.sh
chmod +x llvm.sh

for i in 17 23;
do
	./llvm.sh $i
done

echo "Cloning the repository"

cd /
git clone --recursive --jobs $(nproc) https://github.com/SChernykh/p2pool

echo "Deleting temporary files"

cd /root
rm -rf *

echo "All done"
