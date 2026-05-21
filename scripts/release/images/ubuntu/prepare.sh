#!/bin/bash

# Fail early if something goes wrong

set -u
set -e
set -o pipefail

# Software versions to install

APT_SNAPSHOT=20260521T000000Z

_7ZIP_VERSION_MAJOR=26
_7ZIP_VERSION_MINOR=01
_7ZIP_SHA256="8ea0fc8a135e7b848e80a4116fe22dff56c8c4518dde1f43cce67f4e340b437a"

BINUTILS_VERSION=2_46
BINUTILS_COMMIT_HASH=49d4d3fafa4ec4ff5a3460d91d5b1ed5286487db

CLANG_VERSION=22.1.6
CLANG_COMMIT_HASH=fc4aad7b5db3fff421df9a9637605b9ca5667881

CMAKE_VERSION_MAJOR=4.3
CMAKE_VERSION=4.3.2
CMAKE_SHA256="791ae3604841ca03cb3889a3ad89165346e4b180ae3448efd4b0caa9ef46d245"

FREEBSD_VERSION=12.4
FREEBSD_AARCH64_SHA256="6c401819bfb93e810c9f9aa670a1e4685f924df5e7e0c9c6397dd6c16c954fa2"
FREEBSD_X86_64_SHA256="581c7edacfd2fca2bdf5791f667402d22fccd8a5e184635e0cac075564d57aa8"

GCC_VERSION=16.1.0
GCC_COMMIT_HASH=6afcc4f6da931eb93f3ab001a0dd9650ea71d1ea

GLIBC_VERSION=2.43
GLIBC_SHA256="d9c86c6b5dbddb43a3e08270c5844fc5177d19442cf5b8df4be7c07cd5fa3831"

LINUX_HEADERS_VERSION=5.10.256
HEADERS_SHA256="f1e9dac8ec41e5bd7b1811158c7b72269696ce1c37fbdd17a898b293b54d8e5f"

MACOSX_SDK_VERSION=26.1
MACOSX_SDK_SHA256="beee7212d265a6d2867d0236cc069314b38d5fb3486a6515734e76fa210c784c"

OSXCROSS_VERSION=2.0-llvm-based
OSXCROSS_COMMIT_HASH=2bc739ebe45db5d72e176d2a4e1c7dd95464e8e2

MAKE_VERSION=4.4.1
MAKE_SHA256="dd16fb1d67bfab79a72f5e8390735c49e3e8e70b4945a15ab1f81ddb78658fb3"

MINGW_VERSION=14.0.0
MINGW_COMMIT_HASH=9b3dd0125792fe94d16cacdc596dbd42fca1b369

XZ_VERSION=5.8.3
XZ_COMMIT_HASH=4b73f2ec19a99ef465282fbce633e8deb33691b3

TAR_VERSION=1.35
TAR_SHA256="4d62ff37342ec7aed748535323930c7cf94acf71c3591882b26a7ea50f3edc16"

echo "Install prerequisites"

export DEBIAN_FRONTEND=noninteractive

# Install ca-certificates normally because APT snapshots require HTTPS
apt-get update
apt-get install -yq --no-install-recommends ca-certificates

echo "APT::Snapshot \"$APT_SNAPSHOT\";" > /etc/apt/apt.conf.d/50snapshot

apt-get update
apt-get install -yq --no-install-recommends curl bzip2 flex texinfo bison ninja-build python3 python3-yaml file rsync xz-utils gawk gettext patch git gcc g++

echo "Cloning the P2Pool repository in background"

cd /
# Get the repository in the image, so it can be quickly switched to a specific commit when building P2Pool releases
git clone --recursive --jobs $(nproc) https://github.com/SChernykh/p2pool &
P2POOL_CLONE_PID=$!

echo "Download archives"

cd /root

MAKE_NAME=make-$MAKE_VERSION
MAKE_FILE=$MAKE_NAME.tar.gz

_7ZIP_FILE=7z$_7ZIP_VERSION_MAJOR$_7ZIP_VERSION_MINOR-linux-x64.tar.xz

CMAKE_NAME=cmake-$CMAKE_VERSION-linux-x86_64
CMAKE_FILE=$CMAKE_NAME.tar.gz

HEADERS_FILE=linux-$LINUX_HEADERS_VERSION.tar.xz

GLIBC_FILE=glibc-$GLIBC_VERSION.tar.xz

MACOSX_SDK_FILE=MacOSX$MACOSX_SDK_VERSION.sdk.tar.xz

FREEBSD_FILE=base.txz

TAR_FILE=tar-$TAR_VERSION.tar.xz

mkdir /usr/local/cross-freebsd-x86_64
mkdir /usr/local/cross-freebsd-aarch64

curl -fL -Z --fail-early --retry 10 --retry-all-errors \
-O https://ftpmirror.gnu.org/make/$MAKE_FILE \
-O https://github.com/ip7z/7zip/releases/download/$_7ZIP_VERSION_MAJOR.$_7ZIP_VERSION_MINOR/$_7ZIP_FILE \
-O https://github.com/Kitware/CMake/releases/download/v$CMAKE_VERSION/$CMAKE_FILE \
-O https://www.kernel.org/pub/linux/kernel/v5.x/$HEADERS_FILE \
-O https://ftpmirror.gnu.org/glibc/$GLIBC_FILE \
-O https://github.com/joseluisq/macosx-sdks/releases/download/$MACOSX_SDK_VERSION/$MACOSX_SDK_FILE \
-o /usr/local/cross-freebsd-x86_64/$FREEBSD_FILE https://archive.freebsd.org/old-releases/amd64/$FREEBSD_VERSION-RELEASE/$FREEBSD_FILE \
-o /usr/local/cross-freebsd-aarch64/$FREEBSD_FILE https://archive.freebsd.org/old-releases/arm64/$FREEBSD_VERSION-RELEASE/$FREEBSD_FILE \
-O https://ftpmirror.gnu.org/tar/$TAR_FILE

echo "Verifying checksums"

cd /root

MAKE_FILE_SHA256="$(sha256sum $MAKE_FILE | awk '{ print $1 }')"

if [ "$MAKE_FILE_SHA256" != "$MAKE_SHA256" ]; then
    echo "Error: SHA256 sum does not match for $MAKE_FILE - expected $MAKE_SHA256, got $MAKE_FILE_SHA256"
    exit 1
fi

_7ZIP_FILE_SHA256="$(sha256sum $_7ZIP_FILE | awk '{ print $1 }')"

if [ "$_7ZIP_FILE_SHA256" != "$_7ZIP_SHA256" ]; then
    echo "Error: SHA256 sum does not match for $_7ZIP_FILE - expected $_7ZIP_SHA256, got $_7ZIP_FILE_SHA256"
    exit 1
fi

CMAKE_FILE_SHA256="$(sha256sum $CMAKE_FILE | awk '{ print $1 }')"

if [ "$CMAKE_FILE_SHA256" != "$CMAKE_SHA256" ]; then
    echo "Error: SHA256 sum does not match for $CMAKE_FILE - expected $CMAKE_SHA256, got $CMAKE_FILE_SHA256"
    exit 1
fi

HEADERS_FILE_SHA256="$(sha256sum $HEADERS_FILE | awk '{ print $1 }')"

if [ "$HEADERS_FILE_SHA256" != "$HEADERS_SHA256" ]; then
    echo "Error: SHA256 sum does not match for $HEADERS_FILE - expected $HEADERS_SHA256, got $HEADERS_FILE_SHA256"
    exit 1
fi

GLIBC_FILE_SHA256="$(sha256sum $GLIBC_FILE | awk '{ print $1 }')"

if [ "$GLIBC_FILE_SHA256" != "$GLIBC_SHA256" ]; then
    echo "Error: SHA256 sum does not match for $GLIBC_FILE - expected $GLIBC_SHA256, got $GLIBC_FILE_SHA256"
    exit 1
fi

MACOSX_SDK_FILE_SHA256="$(sha256sum $MACOSX_SDK_FILE | awk '{ print $1 }')"

if [ "$MACOSX_SDK_FILE_SHA256" != "$MACOSX_SDK_SHA256" ]; then
    echo "Error: SHA256 sum does not match for $MACOSX_SDK_FILE - expected $MACOSX_SDK_SHA256, got $MACOSX_SDK_FILE_SHA256"
    exit 1
fi

cd /usr/local/cross-freebsd-x86_64

FREEBSD_X86_64_FILE_SHA256="$(sha256sum $FREEBSD_FILE | awk '{ print $1 }')"

if [ "$FREEBSD_X86_64_FILE_SHA256" != "$FREEBSD_X86_64_SHA256" ]; then
    echo "Error: SHA256 sum does not match for $FREEBSD_FILE - expected $FREEBSD_X86_64_SHA256, got $FREEBSD_X86_64_FILE_SHA256"
    exit 1
fi

cd /usr/local/cross-freebsd-aarch64

FREEBSD_AARCH64_FILE_SHA256="$(sha256sum $FREEBSD_FILE | awk '{ print $1 }')"

if [ "$FREEBSD_AARCH64_FILE_SHA256" != "$FREEBSD_AARCH64_SHA256" ]; then
    echo "Error: SHA256 sum does not match for $FREEBSD_FILE - expected $FREEBSD_AARCH64_SHA256, got $FREEBSD_AARCH64_FILE_SHA256"
    exit 1
fi

cd /root

TAR_FILE_SHA256="$(sha256sum $TAR_FILE | awk '{ print $1 }')"

if [ "$TAR_FILE_SHA256" != "$TAR_SHA256" ]; then
    echo "Error: SHA256 sum does not match for $TAR_FILE - expected $TAR_SHA256, got $TAR_FILE_SHA256"
    exit 1
fi

echo "Cloning repositories"

cd /root
git clone --branch releases/gcc-$GCC_VERSION https://gcc.gnu.org/git/gcc.git
cd gcc
git checkout $GCC_COMMIT_HASH

cd /root
git clone --branch binutils-$BINUTILS_VERSION https://sourceware.org/git/binutils-gdb.git
cd binutils-gdb
git checkout $BINUTILS_COMMIT_HASH

cd /root
git clone --branch llvmorg-$CLANG_VERSION https://github.com/llvm/llvm-project.git
cd llvm-project
git checkout $CLANG_COMMIT_HASH

cd /root
git clone --branch v$MINGW_VERSION https://git.code.sf.net/p/mingw-w64/mingw-w64 mingw-w64-v$MINGW_VERSION
cd mingw-w64-v$MINGW_VERSION
git checkout $MINGW_COMMIT_HASH

cd /root
git clone --branch $OSXCROSS_VERSION https://github.com/tpoechtrager/osxcross
cd osxcross
git checkout $OSXCROSS_COMMIT_HASH

cd /root
git clone --branch v$XZ_VERSION https://github.com/tukaani-project/xz
cd xz
git checkout $XZ_COMMIT_HASH

cd /root
mv /root/$MACOSX_SDK_FILE osxcross/tarballs/

echo "Install make"

cd /root

tar xvf $MAKE_FILE
cd $MAKE_NAME
CFLAGS='-O2' ./configure --disable-dependency-tracking
./build.sh
./make install

echo "Install 7-zip"

cd /root

tar xf $_7ZIP_FILE
cp -f 7zz /usr/local/bin/7z

echo "Install GCC"

cd /root

rm -rf gcc/.git

cd gcc
contrib/download_prerequisites
cd ..

mkdir gcc_build && cd gcc_build
../gcc/configure --enable-languages=c,c++ --disable-multilib

make -j$(nproc) bootstrap
make install

echo "Install gmp version from GCC"

cd /root/gcc_build/gmp
make install

echo "Install mpfr version from GCC"

cd /root/gcc_build/mpfr
make install

echo "Install binutils"

cd /root

rm -rf binutils-gdb/.git

cp -r binutils-gdb binutils-gdb-aarch64
cp -r binutils-gdb binutils-gdb-riscv64
cp -r binutils-gdb binutils-gdb-w64

cd binutils-gdb

CFLAGS='-std=gnu11 -O2' ./configure
make -j$(nproc)
make install

echo "Install cmake"

cd /root

tar xvf $CMAKE_FILE
cp $CMAKE_NAME/bin/* /usr/local/bin
cp -r $CMAKE_NAME/share/cmake-$CMAKE_VERSION_MAJOR /usr/local/share

echo "Install clang"

cd /root

cd llvm-project
mv /clang_version.patch .
git apply --verbose --ignore-whitespace clang_version.patch

mkdir build && cd build
cmake -G Ninja -DCMAKE_C_COMPILER=gcc -DCMAKE_CXX_COMPILER=g++ -DLLVM_ENABLE_PROJECTS="clang;lld;libc" -DCMAKE_BUILD_TYPE=Release -DLLVM_VERSION_SUFFIX="_p2pool" -DLIBC_WNO_ERROR=ON -DLLVM_APPEND_VC_REV=OFF ../llvm
ninja
ninja install

cd ..
mkdir build_runtimes
cmake -G Ninja -S runtimes -B build_runtimes -DLLVM_ENABLE_RUNTIMES="libcxx;libcxxabi;libunwind" -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++
ninja -C build_runtimes cxx cxxabi unwind
ninja -C build_runtimes install

echo "Install binutils for aarch64-linux-gnu"

cd /root/binutils-gdb-aarch64

CFLAGS='-std=gnu11 -O2' ./configure --target=aarch64-linux-gnu
make -j$(nproc)
make install

echo "Install Linux headers for aarch64-linux-gnu"

cd /root

tar xf linux-$LINUX_HEADERS_VERSION.tar.xz
cd linux-$LINUX_HEADERS_VERSION
make ARCH=arm64 INSTALL_HDR_PATH=/usr/local/aarch64-linux-gnu headers_install

echo "Install GCC for aarch64-linux-gnu"

cd /root

mkdir gcc_build_aarch64 && cd gcc_build_aarch64
../gcc/configure --target=aarch64-linux-gnu --enable-languages=c,c++ --disable-multilib --disable-libatomic
make -j$(nproc) all-gcc
make install-gcc

echo "Install glibc for aarch64-linux-gnu"

cd /root

tar xf $GLIBC_FILE

mkdir glibc_build_aarch64 && cd glibc_build_aarch64
CFLAGS='-O2' ../glibc-$GLIBC_VERSION/configure --build=x86_64-pc-linux-gnu --host=aarch64-linux-gnu --target=aarch64-linux-gnu --prefix=/usr/local/aarch64-linux-gnu --with-headers=/usr/local/aarch64-linux-gnu/include --disable-multilib --disable-sanity-checks libc_cv_forced_unwind=yes --enable-static-nss
make -j$(nproc) install-bootstrap-headers=yes install-headers
make -j$(nproc) csu/subdir_lib
install csu/crt1.o csu/crti.o csu/crtn.o /usr/local/aarch64-linux-gnu/lib

aarch64-linux-gnu-gcc -nostdlib -nostartfiles -shared -x c /dev/null -o /usr/local/aarch64-linux-gnu/lib/libc.so

touch /usr/local/aarch64-linux-gnu/include/gnu/stubs.h

cd /root/gcc_build_aarch64
make -j$(nproc) all-target-libgcc
make install-target-libgcc

cd /root/glibc_build_aarch64
make -j$(nproc)
make install

echo "Finish installing GCC for aarch64-linux-gnu"

cd /root/gcc_build_aarch64
make -j$(nproc) all-target-libstdc++-v3
make install-target-libstdc++-v3

echo "Install binutils for riscv64-linux-gnu"

cd /root/binutils-gdb-riscv64

CFLAGS='-std=gnu11 -O2' ./configure --target=riscv64-linux-gnu
make -j$(nproc)
make install

echo "Install Linux headers for riscv64-linux-gnu"

cd /root/linux-$LINUX_HEADERS_VERSION
make ARCH=riscv INSTALL_HDR_PATH=/usr/local/riscv64-linux-gnu headers_install

echo "Install GCC for riscv64-linux-gnu"

cd /root

mkdir gcc_build_riscv64 && cd gcc_build_riscv64
../gcc/configure --target=riscv64-linux-gnu --enable-languages=c,c++ --disable-multilib --disable-libatomic
make -j$(nproc) all-gcc
make install-gcc

echo "Install glibc for riscv64-linux-gnu"

cd /root

mkdir glibc_build_riscv64 && cd glibc_build_riscv64
CFLAGS='-O2' ../glibc-$GLIBC_VERSION/configure --build=x86_64-pc-linux-gnu --host=riscv64-linux-gnu --target=riscv64-linux-gnu --prefix=/usr/local/riscv64-linux-gnu --with-headers=/usr/local/riscv64-linux-gnu/include --disable-multilib --disable-sanity-checks libc_cv_forced_unwind=yes --enable-static-nss
make -j$(nproc) install-bootstrap-headers=yes install-headers
make -j$(nproc) csu/subdir_lib
install csu/crt1.o csu/crti.o csu/crtn.o /usr/local/riscv64-linux-gnu/lib

riscv64-linux-gnu-gcc -nostdlib -nostartfiles -shared -x c /dev/null -o /usr/local/riscv64-linux-gnu/lib/libc.so

touch /usr/local/riscv64-linux-gnu/include/gnu/stubs.h

cd /root/gcc_build_riscv64
make -j$(nproc) all-target-libgcc
make install-target-libgcc

cd /root/glibc_build_riscv64
make -j$(nproc)
make install

echo "Finish installing GCC for riscv64-linux-gnu"

cd /root/gcc_build_riscv64
make -j$(nproc) all-target-libstdc++-v3
make install-target-libstdc++-v3

echo "Add lib path for lld"

ln -s /usr/local/riscv64-linux-gnu/lib /usr/local/riscv64-linux-gnu/lib64

echo "Install binutils for x86_64-w64-mingw32"

cd /root/binutils-gdb-w64

CFLAGS='-std=gnu11 -O2' ./configure --target=x86_64-w64-mingw32
make -j$(nproc)
make install

echo "Install mingw-w64 headers"

cd /root

rm -rf mingw-w64-v$MINGW_VERSION/.git

cd mingw-w64-v$MINGW_VERSION/mingw-w64-headers
CFLAGS='-O2' ./configure --host=x86_64-w64-mingw32 --prefix=/usr/local/x86_64-w64-mingw32 --with-default-msvcrt=msvcrt --with-default-win32-winnt=0x0600
make install

echo "Install GCC for x86_64-w64-mingw32"

cd /root

mkdir gcc_build_w64 && cd gcc_build_w64
../gcc/configure --target=x86_64-w64-mingw32 --enable-languages=c,c++ --disable-multilib --disable-libatomic
make -j$(nproc) all-gcc
make install-gcc

echo "Install mingw-w64 CRT"

# Need to do it two times for some reason - first time without pthreads, or it will fail to link.
cd /root/mingw-w64-v$MINGW_VERSION
CFLAGS='-O2' ./configure --host=x86_64-w64-mingw32 --prefix=/usr/local/x86_64-w64-mingw32 --with-default-msvcrt=msvcrt --with-default-win32-winnt=0x0600
make -j$(nproc)
make -j$(nproc) install

cd /root/mingw-w64-v$MINGW_VERSION
CFLAGS='-O2' ./configure --host=x86_64-w64-mingw32 --prefix=/usr/local/x86_64-w64-mingw32 --with-default-msvcrt=msvcrt --with-default-win32-winnt=0x0600 --with-libraries=winpthreads
make -j$(nproc)
make -j$(nproc) install

echo "Finish installing GCC for x86_64-w64-mingw32"

cd /root/gcc_build_w64
make -j$(nproc) all-target-libstdc++-v3
make install-target-libstdc++-v3

echo "Install Linux headers for x86_64-pc-linux-gnu"

cd /root

cd /root/linux-$LINUX_HEADERS_VERSION
make ARCH=x86_64 INSTALL_HDR_PATH=/usr/local/x86_64-pc-linux-gnu headers_install

echo "Install glibc for x86_64-pc-linux-gnu"

cd /root

mkdir glibc_build_x86_64 && cd glibc_build_x86_64
CFLAGS='-O2' ../glibc-$GLIBC_VERSION/configure --build=x86_64-pc-linux-gnu --host=x86_64-pc-linux-gnu --target=x86_64-pc-linux-gnu --prefix=/usr/local/x86_64-pc-linux-gnu --with-headers=/usr/local/x86_64-pc-linux-gnu/include --disable-multilib --enable-static-nss
make -j$(nproc) install-bootstrap-headers=yes install-headers
make -j$(nproc) csu/subdir_lib

install csu/crt1.o csu/crti.o csu/crtn.o /usr/local/x86_64-pc-linux-gnu/lib

gcc -nostdlib -nostartfiles -shared -x c /dev/null -o /usr/local/x86_64-pc-linux-gnu/lib/libc.so

make -j$(nproc)
make install

echo "Build MacOSX cross compilers"

cd /root/osxcross
mv /osxcross.patch .
git apply --verbose --ignore-whitespace osxcross.patch

TARGET_DIR=/usr/local OSX_VERSION_MIN=10.15 UNATTENDED=1 ./build.sh
./build_compiler_rt.sh

echo "Install FreeBSD $FREEBSD_VERSION SDK"

cd /usr/local/cross-freebsd-x86_64

tar -xf $FREEBSD_FILE ./lib/ ./usr/lib/ ./usr/include/
rm $FREEBSD_FILE
#find /usr/local/cross-freebsd-x86_64/usr/lib -xtype l|xargs ls -l|grep ' /lib/'|awk '{print "ln -sf /usr/local/cross-freebsd-x86_64"$11 " " $9}'|/bin/sh

cd /usr/local/cross-freebsd-aarch64

tar -xf $FREEBSD_FILE ./lib/ ./usr/lib/ ./usr/include/
rm $FREEBSD_FILE
#find /usr/local/cross-freebsd-aarch64/usr/lib -xtype l|xargs ls -l|grep ' /lib/'|awk '{print "ln -sf /usr/local/cross-freebsd-aarch64"$11 " " $9}'|/bin/sh

echo "Install xz"

apt-get remove -yq xz-utils

cd /root

cd xz
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)

cp -f lzma* /usr/bin
cp -f xz* /usr/bin

echo "Install tar"

cd /root

tar xvf $TAR_FILE
cd tar-$TAR_VERSION
FORCE_UNSAFE_CONFIGURE=1 CFLAGS='-O2' ./configure
make -j$(nproc)
make install

echo "Cleaning up APT packages"

apt-get remove -yq curl bzip2 flex texinfo bison ninja-build python3 python3-yaml file rsync gawk gettext patch
apt-get autoremove -yq --purge
apt-get clean
rm -rf /var/lib/apt/lists/*

echo "Waiting for P2Pool git clone to finish"
wait $P2POOL_CLONE_PID

echo "Deleting system glibc files to force our glibc"

rm -f /usr/lib/x86_64-linux-gnu/crt1.o
rm -f /usr/lib/x86_64-linux-gnu/crti.o
rm -f /usr/lib/x86_64-linux-gnu/crtn.o
rm -f /usr/lib/x86_64-linux-gnu/libc.a

echo "Deleting temporary files"

rm -rf /root/*
rm -rf /tmp/*

echo "All done"
