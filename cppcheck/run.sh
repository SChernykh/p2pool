#!/bin/bash
../cppcheck-main/cppcheck --project=../build/compile_commands.json -DSIZE_MAX=UINT64_MAX -DRAPIDJSON_ENDIAN=RAPIDJSON_LITTLEENDIAN -D__SSE2__=1 -D__BYTE_ORDER__=1 -D__ORDER_LITTLE_ENDIAN__=1 -D__linux__=1 --platform=unix64 --std=c++17 --enable=all --inconclusive --inline-suppr --template="{file}:{line}:{id}{inconclusive: INCONCLUSIVE} {message}" --suppressions-list=suppressions.txt --output-file=errors_full.txt --max-ctu-depth=3 --check-level=exhaustive --checkers-report=checkers_report.txt
grep -v 'external' errors_full.txt > errors_filtered0.txt
grep -v ':checkersReport' errors_filtered0.txt > errors_filtered.txt
if [ -s errors_filtered.txt ]; then
	cat errors_filtered.txt
	exit 1
fi
