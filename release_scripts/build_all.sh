#!/bin/sh

# Example usage:
#
# git clone --recursive https://github.com/SChernykh/p2pool
# cd p2pool
# git checkout v4.9
# release_scripts/build_all.sh v4.9
#

cd "$(dirname "$0")"

docker images | grep -q p2pool_build_ubuntu

if [ $? -ne 0 ]; then
	echo "Build image not found, creating it"
	images/ubuntu/build.sh
fi

rm -f p2pool.tar
tar -f p2pool.tar -c ../cmake -c ../external -c ../src -c ../CMakeLists.txt -c ../LICENSE -c ../README.md

ln p2pool.tar linux_aarch64/p2pool.tar
ln p2pool.tar linux_riscv64/p2pool.tar
ln p2pool.tar linux_x64/p2pool.tar
ln p2pool.tar windows_x64/p2pool.tar

gnome-terminal --tab -- linux_aarch64/build.sh $1
gnome-terminal --tab -- linux_riscv64/build.sh $1
gnome-terminal --tab -- linux_x64/build.sh $1
gnome-terminal --tab -- windows_x64/build.sh $1
