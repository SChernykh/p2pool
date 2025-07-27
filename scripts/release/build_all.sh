#!/bin/sh

# Example usage: release_scripts/build_all.sh v4.9

cd "$(dirname "$0")"

docker images | grep -q p2pool_build_ubuntu

if [ $? -ne 0 ]; then
	echo "Build image not found, creating it"
	images/ubuntu/build.sh
fi

N=$(($(nproc)-1))
N1=$(($N/2))
N2=$(($N1+1))

gnome-terminal --tab -- freebsd_aarch64/build.sh $1 0-$N1
gnome-terminal --tab -- freebsd_x64/build.sh $1 $N2-$N
gnome-terminal --tab -- linux_aarch64/build.sh $1 0-$N1
gnome-terminal --tab -- linux_riscv64/build.sh $1 $N2-$N
gnome-terminal --tab -- linux_x64/build.sh $1 0-$N1
gnome-terminal --tab -- windows_x64/build.sh $1 $N2-$N
gnome-terminal --tab -- macos_aarch64/build.sh $1 0-$N1
gnome-terminal --tab -- macos_x64/build.sh $1 $N2-$N
gnome-terminal --tab -- source/build.sh $1 0-$N1
