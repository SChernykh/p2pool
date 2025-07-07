#!/bin/sh
set -e

cd /p2pool
git fetch --jobs=$(nproc)
git checkout $1
git submodule update --recursive --jobs $(nproc)

export TZ=UTC0

BUILD_TIMESTAMP=$(git show --no-patch --format=%ct $1)
CURRENT_DATE=$(date -u -d @$BUILD_TIMESTAMP +"%Y-%m-%d")
CURRENT_TIME=$(date -u -d @$BUILD_TIMESTAMP +"%H:%M:%S")
TOUCH_DATE=$(date -u -d @$BUILD_TIMESTAMP +"%Y%m%d%H%M.%S")

cd /

tar --format=pax --pax-option='exthdr.name=%d/PaxHeaders/%f,delete=atime,delete=ctime' --sort=name --owner=0 --group=0 --mtime="$CURRENT_DATE $CURRENT_TIME" --exclude=".git" -f p2pool_source-$1.tar -c p2pool
touch -t $TOUCH_DATE p2pool_source-$1.tar

xz --version
xz --lzma2=preset=9e,dict=256MiB,pb=0 p2pool_source-$1.tar
