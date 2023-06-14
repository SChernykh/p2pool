#!/bin/bash
../cppcheck-main/cppcheck -DSIZE_MAX=UINT64_MAX -DRAPIDJSON_ENDIAN=RAPIDJSON_LITTLEENDIAN -DMINIUPNP_STATICLIB -DRAPIDJSON_PARSE_DEFAULT_FLAGS=kParseTrailingCommasFlag -DWITH_RANDOMX -DWITH_UPNP -DZMQ_STATIC -DZMQ_CPP11 -DZMQ_CPP14 --platform=unix64 --std=c++14 --enable=all --inconclusive --inline-suppr --template="{file}:{line}:{id}{inconclusive: INCONCLUSIVE} {message}" --includes-file=includes.txt --suppressions-list=suppressions.txt --output-file=errors_full.txt --max-ctu-depth=3 ../src
grep -v 'external' errors_full.txt > errors_filtered.txt
if [ -s errors_filtered.txt ]; then
	cat errors_filtered.txt
	exit 1
fi
