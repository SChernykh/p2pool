#!/bin/sh
set -e

export TZ=UTC0

CURRENT_DATE=$(date -u -d @$2 +"%Y-%m-%d")
CURRENT_TIME=$(date -u -d @$2 +"%H:%M:%S")
TOUCH_DATE=$(date -u -d @$2 +"%Y%m%d%H%M.%S")

cd /root

git clone --depth=1 --recursive --branch $1 https://github.com/SChernykh/p2pool

tar --format=pax --pax-option='exthdr.name=%d/PaxHeaders/%f,delete=atime,delete=ctime' --sort=name --owner=0 --group=0 --mtime="$CURRENT_DATE $CURRENT_TIME" --exclude=".git" --exclude="release_scripts/*.tar*" -f p2pool_source-$1.tar -c p2pool
touch -t $TOUCH_DATE p2pool_source-$1.tar

xz --version
xz --lzma2=preset=9e,dict=256MiB,pb=0 p2pool_source-$1.tar
