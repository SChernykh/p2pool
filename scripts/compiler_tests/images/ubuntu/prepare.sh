#!/bin/sh
set -e

echo "Installing prerequisites"

export DEBIAN_FRONTEND=noninteractive

apt-get update && apt-get upgrade -yq --no-install-recommends
apt-get install -yq --no-install-recommends ca-certificates curl bzip2 flex git gcc g++ cmake make libuv1-dev libzmq3-dev libsodium-dev libpgm-dev libnorm-dev libgss-dev libcurl4-openssl-dev libidn2-0-dev

echo "Installing GCC 8.5.0"

cd /root

git clone --depth 1 --branch releases/gcc-8.5.0 --jobs $(nproc) git://gcc.gnu.org/git/gcc.git gcc-8

cd gcc-8
contrib/download_prerequisites

mkdir build && cd build
../configure --enable-languages=c,c++ --disable-multilib --disable-bootstrap --prefix=/usr/local/gcc-8
make -j$(nproc)
make install

echo "Installing GCC 9.5.0"

cd /root

git clone --depth 1 --branch releases/gcc-9.5.0 --jobs $(nproc) git://gcc.gnu.org/git/gcc.git gcc-9

cd gcc-9
contrib/download_prerequisites

mkdir build && cd build
../configure --enable-languages=c,c++ --disable-multilib --disable-bootstrap --prefix=/usr/local/gcc-9
make -j$(nproc)
make install

echo "Installing GCC 10.5.0"

cd /root

git clone --depth 1 --branch releases/gcc-10.5.0 --jobs $(nproc) git://gcc.gnu.org/git/gcc.git gcc-10

cd gcc-10
contrib/download_prerequisites

mkdir build && cd build
../configure --enable-languages=c,c++ --disable-multilib --disable-bootstrap --prefix=/usr/local/gcc-10
make -j$(nproc)
make install

echo "Installing GCC 11.5.0"

cd /root

git clone --depth 1 --branch releases/gcc-11.5.0 --jobs $(nproc) git://gcc.gnu.org/git/gcc.git gcc-11

cd gcc-11
contrib/download_prerequisites

mkdir build && cd build
../configure --enable-languages=c,c++ --disable-multilib --disable-bootstrap --prefix=/usr/local/gcc-11
make -j$(nproc)
make install

echo "Installing GCC 12.4.0"

cd /root

git clone --depth 1 --branch releases/gcc-12.4.0 --jobs $(nproc) git://gcc.gnu.org/git/gcc.git gcc-12

cd gcc-12
contrib/download_prerequisites

mkdir build && cd build
../configure --enable-languages=c,c++ --disable-multilib --disable-bootstrap --prefix=/usr/local/gcc-12
make -j$(nproc)
make install

echo "Installing GCC 13.4.0"

cd /root

git clone --depth 1 --branch releases/gcc-13.4.0 --jobs $(nproc) git://gcc.gnu.org/git/gcc.git gcc-13

cd gcc-13
contrib/download_prerequisites

mkdir build && cd build
../configure --enable-languages=c,c++ --disable-multilib --disable-bootstrap --prefix=/usr/local/gcc-13
make -j$(nproc)
make install

echo "Installing GCC 14.3.0"

cd /root

git clone --depth 1 --branch releases/gcc-14.3.0 --jobs $(nproc) git://gcc.gnu.org/git/gcc.git gcc-14

cd gcc-14
contrib/download_prerequisites

mkdir build && cd build
../configure --enable-languages=c,c++ --disable-multilib --disable-bootstrap --prefix=/usr/local/gcc-14
make -j$(nproc)
make install

echo "Installing GCC 15.1.0"

cd /root

git clone --depth 1 --branch releases/gcc-15.1.0 --jobs $(nproc) git://gcc.gnu.org/git/gcc.git gcc-15

cd gcc-15
contrib/download_prerequisites

mkdir build && cd build
../configure --enable-languages=c,c++ --disable-multilib --disable-bootstrap --prefix=/usr/local/gcc-15
make -j$(nproc)
make install

echo "Cloning the repository"

cd /
git clone --recursive --jobs $(nproc) https://github.com/SChernykh/p2pool

echo "Deleting temporary files"

cd /root
rm -rf *

echo "All done"
