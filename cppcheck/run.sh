#!/bin/bash
../cppcheck-main/cppcheck --project=../build/compile_commands.json -D__cppcheck__ -DSIZE_MAX=UINT64_MAX -DRAPIDJSON_ENDIAN=RAPIDJSON_LITTLEENDIAN -DRAPIDJSON_64BIT=1 -D__SSE2__=1 -D__BYTE_ORDER__=1 -D__ORDER_LITTLE_ENDIAN__=1 -D__linux__=1 -D__x86_64 -D_M_AMD64 -D_M_X64 --platform=unix64 --std=c++17 --enable=all --inconclusive --inline-suppr --template="{file}:{line}:{id}{inconclusive: INCONCLUSIVE} {message}" --suppressions-list=suppressions.txt --output-file=errors_full.txt --max-ctu-depth=3 --check-level=exhaustive --checkers-report=checkers_report.txt

grep -v 'external' errors_full.txt > errors_filtered0.txt
grep -v ':checkersReport' errors_filtered0.txt > errors_filtered.txt

grep 'There were critical errors' checkers_report.txt > checkers_report_filtered.txt

if [ -s errors_filtered.txt ]; then
	cat errors_filtered.txt
	exit 1
fi

if [ -s checkers_report_filtered.txt ]; then
	cat checkers_report_filtered.txt
	exit 1
fi
