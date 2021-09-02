@echo off
"C:\Program Files\cppcheck\cppcheck.exe" --project=..\build\p2pool.vcxproj --project-configuration="Release|x64" -DZMQ_STATIC --platform=win64 --std=c++14 --enable=all --inconclusive --inline-suppr --template="{file}:{line}:{id}{inconclusive: INCONCLUSIVE} {message}" --includes-file=includes.txt --suppressions-list=suppressions.txt --output-file=errors_full.txt
findstr /V /C:"external\src" errors_full.txt > errors_filtered.txt
