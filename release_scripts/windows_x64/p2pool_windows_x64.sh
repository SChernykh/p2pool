#!/bin/sh

export TZ=UTC0

CURRENT_DATE=$(date -u -d @$2 +"%Y-%m-%d")
CURRENT_TIME=$(date -u -d @$2 +"%H:%M:%S")
TOUCH_DATE=$(date -u -d @$2 +"%Y%m%d%H%M.%S")

cd /p2pool
cp /usr/x86_64-w64-mingw32/include/psdk_inc/intrin-impl.h intrin-impl.h
patch -u intrin-impl.h -i intrin-impl.patch
cp -f intrin-impl.h /usr/x86_64-w64-mingw32/include/psdk_inc/intrin-impl.h
rm intrin-impl.h

flags_libs="--target=x86_64-pc-windows-gnu -Os -flto -ffunction-sections -fdata-sections -Wl,-s -Wl,--gc-sections -Wl,/timestamp:$2 -fuse-ld=lld -w"
flags_p2pool="--target=x86_64-pc-windows-gnu -ffunction-sections -fdata-sections -Wl,-s -Wl,--gc-sections -Wl,/timestamp:$2 -fuse-ld=lld -femulated-tls -Wno-unused-command-line-argument"

cd /p2pool/external/src/curl
cmake . -DCMAKE_BUILD_TYPE=Release -DCMAKE_TOOLCHAIN_FILE=../../../cmake/windows_x86_64_toolchain_clang.cmake -DCMAKE_C_FLAGS="$flags_libs" -DBUILD_CURL_EXE=OFF -DBUILD_SHARED_LIBS=OFF -DCURL_DISABLE_INSTALL=ON -DCURL_ENABLE_EXPORT_TARGET=OFF -DCURL_DISABLE_HEADERS_API=ON -DCURL_DISABLE_BINDLOCAL=ON -DBUILD_LIBCURL_DOCS=OFF -DBUILD_MISC_DOCS=OFF -DENABLE_CURL_MANUAL=OFF -DCURL_ZLIB=OFF -DCURL_BROTLI=OFF -DCURL_ZSTD=OFF -DCURL_DISABLE_ALTSVC=ON -DCURL_DISABLE_COOKIES=ON -DCURL_DISABLE_DOH=ON -DCURL_DISABLE_GETOPTIONS=ON -DCURL_DISABLE_HSTS=ON -DCURL_DISABLE_LIBCURL_OPTION=ON -DCURL_DISABLE_MIME=ON -DCURL_DISABLE_NETRC=ON -DCURL_DISABLE_NTLM=ON -DCURL_DISABLE_PARSEDATE=ON -DCURL_DISABLE_PROGRESS_METER=ON -DCURL_DISABLE_SHUFFLE_DNS=ON -DCURL_DISABLE_SOCKETPAIR=ON -DCURL_DISABLE_VERBOSE_STRINGS=ON -DCURL_DISABLE_WEBSOCKETS=ON -DHTTP_ONLY=ON -DCURL_ENABLE_SSL=OFF -DUSE_LIBIDN2=OFF -DCURL_USE_LIBPSL=OFF -DCURL_USE_LIBSSH2=OFF -DENABLE_UNIX_SOCKETS=OFF -DBUILD_TESTING=OFF -DUSE_NGHTTP2=OFF -DBUILD_EXAMPLES=OFF -DP2POOL_BORINGSSL=ON -DCURL_DISABLE_SRP=ON -DOPENSSL_INCLUDE_DIR=../grpc/third_party/boringssl-with-bazel/src/include
make -j$(nproc)
cd lib && cp -f libcurl.a .libs

cd /p2pool/external/src/libuv
rm -rf build
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_TOOLCHAIN_FILE=../../../../cmake/windows_x86_64_toolchain_clang.cmake -DCMAKE_C_FLAGS="$flags_libs" -DBUILD_TESTING=OFF -DLIBUV_BUILD_SHARED=OFF
make -j$(nproc)

cd /p2pool/external/src/libzmq
rm -rf build
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_TOOLCHAIN_FILE=../../../../cmake/windows_x86_64_toolchain_clang.cmake -DCMAKE_C_FLAGS="$flags_libs" -DCMAKE_CXX_FLAGS="$flags_libs" -DWITH_LIBSODIUM=OFF -DWITH_LIBBSD=OFF -DBUILD_TESTS=OFF -DWITH_DOCS=OFF -DENABLE_DRAFTS=OFF -DBUILD_SHARED=OFF -DPOLLER=epoll
make -j$(nproc)

cd /p2pool
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_TOOLCHAIN_FILE=../cmake/windows_x86_64_toolchain_clang.cmake -DCMAKE_C_FLAGS="$flags_p2pool" -DCMAKE_CXX_FLAGS="$flags_p2pool" -DOPENSSL_NO_ASM=ON -DSTATIC_BINARY=ON -DARCH_ID=x86_64
make -j$(nproc) p2pool

mkdir $1

mv p2pool.exe $1
mv ../LICENSE $1
mv ../README.md $1

touch -t $TOUCH_DATE $1
touch -t $TOUCH_DATE $1/*
7z a -mx=9 -tzip -stl $1.zip $1
