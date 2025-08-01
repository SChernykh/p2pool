#!/bin/sh

# Example usage: build_all.sh v4.8.1

cd "$(dirname "$0")"

docker images | grep -q p2pool_compiler_tests_ubuntu

if [ $? -ne 0 ]; then
	echo "Build image not found, creating it"
	images/ubuntu/build.sh
fi

for i in 8 15;
do
	gcc/build.sh $1 $i
done

for i in 17 21;
do
	clang/build.sh $1 $i
done
