#!/bin/sh
set -e

cd /p2pool
git fetch --jobs=$(nproc)
git checkout $2
git submodule update --recursive --jobs $(nproc)

export TZ=UTC0

BUILD_TIMESTAMP=$(git show --no-patch --format=%ct $2)
CURRENT_DATE=$(date -u -d @$BUILD_TIMESTAMP +"%Y-%m-%d")
CURRENT_TIME=$(date -u -d @$BUILD_TIMESTAMP +"%H:%M:%S")
TOUCH_DATE=$(date -u -d @$BUILD_TIMESTAMP +"%Y%m%d%H%M.%S")

flags_size="-ffunction-sections -fdata-sections -Wl,-s -Wl,--gc-sections"
flags_datetime="-D__DATE__=\"\\\"$CURRENT_DATE\\\"\" -D__TIME__=\"\\\"$CURRENT_TIME\\\"\" -Wno-builtin-macro-redefined"

flags_libs="--target=x86_64-pc-windows-gnu -Os -flto -Wl,/timestamp:$BUILD_TIMESTAMP -fuse-ld=lld -w $flags_size $flags_datetime"

flags_p2pool="--target=x86_64-pc-windows-gnu -Wl,/timestamp:$BUILD_TIMESTAMP -fuse-ld=lld -femulated-tls -Wno-unused-command-line-argument $flags_size $flags_datetime"
flags_cxx_headers="-isystem /usr/local/x86_64-w64-mingw32/include/c++ -isystem /usr/local/x86_64-w64-mingw32/include/c++/15.1.0 -isystem /usr/local/x86_64-w64-mingw32/include"

cd /p2pool
git apply --verbose --ignore-whitespace --directory=external/src/grpc/third_party/boringssl-with-bazel patches/boringssl/win7.patch

cd /p2pool/external/src/curl
cmake . -DCMAKE_BUILD_TYPE=MinSizeRel -DCMAKE_TOOLCHAIN_FILE=../../../cmake/windows_x86_64_toolchain_clang.cmake -DCMAKE_C_FLAGS="$flags_libs" -DBUILD_CURL_EXE=OFF -DBUILD_SHARED_LIBS=OFF -DCURL_DISABLE_INSTALL=ON -DCURL_ENABLE_EXPORT_TARGET=OFF -DCURL_DISABLE_HEADERS_API=ON -DCURL_DISABLE_BINDLOCAL=ON -DBUILD_LIBCURL_DOCS=OFF -DBUILD_MISC_DOCS=OFF -DENABLE_CURL_MANUAL=OFF -DCURL_ZLIB=OFF -DCURL_BROTLI=OFF -DCURL_ZSTD=OFF -DCURL_DISABLE_ALTSVC=ON -DCURL_DISABLE_COOKIES=ON -DCURL_DISABLE_DOH=ON -DCURL_DISABLE_GETOPTIONS=ON -DCURL_DISABLE_HSTS=ON -DCURL_DISABLE_LIBCURL_OPTION=ON -DCURL_DISABLE_MIME=ON -DCURL_DISABLE_NETRC=ON -DCURL_DISABLE_NTLM=ON -DCURL_DISABLE_PARSEDATE=ON -DCURL_DISABLE_PROGRESS_METER=ON -DCURL_DISABLE_SHUFFLE_DNS=ON -DCURL_DISABLE_SOCKETPAIR=ON -DCURL_DISABLE_VERBOSE_STRINGS=ON -DCURL_DISABLE_WEBSOCKETS=ON -DHTTP_ONLY=ON -DCURL_ENABLE_SSL=OFF -DUSE_LIBIDN2=OFF -DCURL_USE_LIBPSL=OFF -DCURL_USE_LIBSSH2=OFF -DENABLE_UNIX_SOCKETS=OFF -DBUILD_TESTING=OFF -DUSE_NGHTTP2=OFF -DBUILD_EXAMPLES=OFF -DP2POOL_BORINGSSL=ON -DCURL_DISABLE_SRP=ON -DCURL_DISABLE_AWS=ON -DCURL_DISABLE_BASIC_AUTH=ON -DCURL_DISABLE_BEARER_AUTH=ON -DCURL_DISABLE_KERBEROS_AUTH=ON -DCURL_DISABLE_NEGOTIATE_AUTH=ON -DOPENSSL_INCLUDE_DIR=../grpc/third_party/boringssl-with-bazel/src/include
make -j$(nproc)
cd lib && cp -f libcurl.a .libs

cd /p2pool/external/src/libuv
rm -rf build
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=MinSizeRel -DCMAKE_TOOLCHAIN_FILE=../../../../cmake/windows_x86_64_toolchain_clang.cmake -DCMAKE_C_FLAGS="$flags_libs" -DBUILD_TESTING=OFF -DLIBUV_BUILD_SHARED=OFF
make -j$(nproc)

cd /p2pool/external/src/libzmq
rm -rf build
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=MinSizeRel -DCMAKE_TOOLCHAIN_FILE=../../../../cmake/windows_x86_64_toolchain_clang.cmake -DCMAKE_C_FLAGS="$flags_libs" -DCMAKE_CXX_FLAGS="$flags_libs" -DWITH_LIBSODIUM=OFF -DWITH_LIBBSD=OFF -DBUILD_TESTS=OFF -DWITH_DOCS=OFF -DENABLE_DRAFTS=OFF -DBUILD_SHARED=OFF -DPOLLER=epoll
make -j$(nproc)

cd /p2pool
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_POLICY_VERSION_MINIMUM="3.5" -DCMAKE_TOOLCHAIN_FILE=../cmake/windows_x86_64_toolchain_clang.cmake -DCMAKE_C_FLAGS="$flags_p2pool" -DCMAKE_CXX_FLAGS="$flags_p2pool $flags_cxx_headers" -DOPENSSL_NO_ASM=ON -DSTATIC_BINARY=ON -DARCH_ID=x86_64
make -j$(nproc) p2pool

mkdir $1

mv p2pool.exe $1
mv ../LICENSE $1
mv ../README.md $1

chmod -R 0644 $1
chmod 0755 $1/p2pool.exe

touch -t $TOUCH_DATE $1
touch -t $TOUCH_DATE $1/*
7z a -tzip -mx9 -mfb256 -stl $1.zip $1
