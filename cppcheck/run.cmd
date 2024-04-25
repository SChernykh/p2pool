@echo off
"..\cppcheck-main\bin\cppcheck.exe" ../src/*.cpp -DSIZE_MAX=UINT64_MAX -DRAPIDJSON_ENDIAN=RAPIDJSON_LITTLEENDIAN -D_WIN32=1 -D_WIN64=1 -DWIN32=1 -D_WINDOWS=1 -DNDEBUG=1 -DWITH_GRPC=1 -DPROTOBUF_ENABLE_DEBUG_LOGGING_MAY_LEAK_PII=0 -DWITH_RANDOMX=1 -DWITH_UPNP=1 -DCURL_STATICLIB=1 -DWIN32_LEAN_AND_MEAN=1 -D_WIN32_WINNT=0x0600 -D_DISABLE_VECTOR_ANNOTATION=1 -D_DISABLE_STRING_ANNOTATION=1 -DZMQ_STATIC=1 -DHAVE_BITSCANREVERSE64=1 -DRAPIDJSON_PARSE_DEFAULT_FLAGS=kParseTrailingCommasFlag -DMINIUPNP_STATICLIB=1 -DCARES_STATICLIB=1 -DCMAKE_INTDIR="Release" -D__SSE2__=1 -D_MSC_VER=1900 -D__COVERITY__ --platform=win64 --std=c++17 --enable=all --inconclusive --inline-suppr --template="{file}:{line}:{id}{inconclusive: INCONCLUSIVE} {message}" --includes-file=includes.txt --suppressions-list=suppressions.txt --output-file=errors_full.txt --max-ctu-depth=3 --check-level=exhaustive
findstr /V /C:"external\src" errors_full.txt > errors_filtered0.txt
findstr /V /C:":checkersReport" errors_filtered0.txt > errors_filtered.txt
for /f %%i in ("errors_filtered.txt") do set size=%%~zi
if %size% gtr 0 (
	type errors_filtered.txt
	exit 1
)
