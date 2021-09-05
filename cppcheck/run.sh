#!/bin/bash
cppcheck ../src -DZMQ_STATIC --platform=unix64 --std=c++14 --enable=all --inconclusive --inline-suppr --template="{file}:{line}:{id}{inconclusive: INCONCLUSIVE} {message}" -I ../src/ -I ../external/src/ -I ../external/src/cryptonote/ -I ../external/src/libuv/ -I ../external/src/cppzmq/ -I ../external/src/libzmq/ -I ../external/src/llhttp/ -I ../external/src/randomx/src/ --suppressions-list=suppressions.txt --output-file=errors_full.txt
grep -v 'external' errors_full.txt | grep -v 'unmatchedSuppression' > errors_filtered.txt
if [ -s errors_filtered.txt ]; then
	cat errors_filtered.txt
	exit 1
fi
