#!/bin/sh
set -e

OUTPUT_FILE=sha256sums.txt
> $OUTPUT_FILE

format_size() {
	bytes=$1
	if [ $bytes -lt 104857600 ]; then
		kib=$(( bytes / 1024 ))
		echo "${bytes} bytes : ${kib} KiB"
	else
		mib=$(( bytes / 1048576 ))
		echo "${bytes} bytes : ${mib} MiB"
	fi
}

first=1

for file in *.tar.gz *.zip *.tar.xz; do
	size=$(stat -c %s "$file")
	size_fmt=$(format_size "$size")
	sha=$(sha256sum "$file" | awk '{print $1}')

	if [ $first -eq 0 ]; then
		echo >> $OUTPUT_FILE
	fi

	echo "Name: $file" >> $OUTPUT_FILE
	echo "Size: $size_fmt" >> $OUTPUT_FILE
	echo "SHA256: $sha" >> $OUTPUT_FILE

	first=0
done
