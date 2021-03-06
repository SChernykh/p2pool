#!/bin/bash
../cppcheck-main/cppcheck ../src -DSIZE_MAX=UINT64_MAX -DRAPIDJSON_ENDIAN=RAPIDJSON_LITTLEENDIAN --platform=unix64 --std=c++14 --enable=all --inconclusive --inline-suppr --template="{file}:{line}:{id}{inconclusive: INCONCLUSIVE} {message}" --includes-file=includes.txt --suppressions-list=suppressions.txt --output-file=errors_full.txt
grep -v 'external' errors_full.txt > errors_filtered.txt
if [ -s errors_filtered.txt ]; then
	cat errors_filtered.txt
	exit 1
fi
