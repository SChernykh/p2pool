#!/bin/sh
set -e

# Software versions to install

_7ZIP_VERSION=2409
BINUTILS_VERSION=2_44
CLANG_VERSION=20.1.7
CMAKE_VERSION=4.0.3
FREEBSD_VERSION=12.4
GCC_VERSION=15.1.0
GLIBC_VERSION=2.41
LINUX_HEADERS_VERSION=6.15.4
MACOSX_SDK_VERSION=15.5
MAKE_VERSION=4.4.1
MINGW_VERSION=12.0.0
XZ_VERSION=5.8.1

_7ZIP_SHA256="914c7e20ad5ef8e4d3cf08620ff8894b28fe11b7eb99809d6930870fbe48a281"
CMAKE_SHA256="585ae9e013107bc8e7c7c9ce872cbdcbdff569e675b07ef57aacfb88c886faac"
FREEBSD_AARCH64_SHA256="6c401819bfb93e810c9f9aa670a1e4685f924df5e7e0c9c6397dd6c16c954fa2"
FREEBSD_X86_64_SHA256="581c7edacfd2fca2bdf5791f667402d22fccd8a5e184635e0cac075564d57aa8"
GLIBC_SHA256="a5a26b22f545d6b7d7b3dd828e11e428f24f4fac43c934fb071b6a7d0828e901"
HEADERS_SHA256="0eafd627b602f58d73917d00e4fc3196ba18cba67df6995a42aa74744d8efa16"
MACOSX_SDK_SHA256="c15cf0f3f17d714d1aa5a642da8e118db53d79429eb015771ba816aa7c6c1cbd"
MAKE_SHA256="dd16fb1d67bfab79a72f5e8390735c49e3e8e70b4945a15ab1f81ddb78658fb3"

echo "Install prerequisites"

export DEBIAN_FRONTEND=noninteractive

apt-get update && apt-get upgrade -yq --no-install-recommends
apt-get install -yq --no-install-recommends ca-certificates curl bzip2 flex texinfo bison ninja-build python3 file rsync xz-utils gawk gettext patch git gcc g++ make

echo "Install 7-zip"

cd /root

_7ZIP_FILE=7z$_7ZIP_VERSION-linux-x64.tar.xz

curl -L -O https://7-zip.org/a/$_7ZIP_FILE

_7ZIP_FILE_SHA256="$(sha256sum $_7ZIP_FILE | awk '{ print $1 }')"

if [ $_7ZIP_FILE_SHA256 != $_7ZIP_SHA256 ]; then
    echo "Error: SHA256 sum does not match for $_7ZIP_FILE - expected $_7ZIP_SHA256, got $_7ZIP_FILE_SHA256"
    exit 1
fi

tar xf $_7ZIP_FILE
cp -f 7zz /usr/local/bin/7z

echo "Install GCC"

cd /root

git clone --depth 1 --branch releases/gcc-$GCC_VERSION git://gcc.gnu.org/git/gcc.git
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

git clone --depth 1 --branch binutils-$BINUTILS_VERSION git://sourceware.org/git/binutils-gdb.git
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

CMAKE_NAME=cmake-$CMAKE_VERSION-linux-x86_64
CMAKE_FILE=$CMAKE_NAME.tar.gz

curl -L -O https://github.com/Kitware/CMake/releases/download/v$CMAKE_VERSION/$CMAKE_FILE

CMAKE_FILE_SHA256="$(sha256sum $CMAKE_FILE | awk '{ print $1 }')"

if [ $CMAKE_FILE_SHA256 != $CMAKE_SHA256 ]; then
    echo "Error: SHA256 sum does not match for $CMAKE_FILE - expected $CMAKE_SHA256, got $CMAKE_FILE_SHA256"
    exit 1
fi

tar xvf $CMAKE_FILE
cp $CMAKE_NAME/bin/* /usr/local/bin
cp -r $CMAKE_NAME/share/cmake-4.0 /usr/local/share

echo "Install make"

cd /root

MAKE_NAME=make-$MAKE_VERSION
MAKE_FILE=$MAKE_NAME.tar.gz

curl -L -O https://ftpmirror.gnu.org/make/$MAKE_FILE

MAKE_FILE_SHA256="$(sha256sum $MAKE_FILE | awk '{ print $1 }')"

if [ $MAKE_FILE_SHA256 != $MAKE_SHA256 ]; then
    echo "Error: SHA256 sum does not match for $MAKE_FILE - expected $MAKE_SHA256, got $MAKE_FILE_SHA256"
    exit 1
fi

tar xvf $MAKE_FILE
cd $MAKE_NAME
CFLAGS='-O2' ./configure
make
cp -f make /usr/bin

echo "Install clang"

cd /root

git clone --depth 1 --branch llvmorg-$CLANG_VERSION https://github.com/llvm/llvm-project.git

cd llvm-project
mkdir build && cd build
cmake -G Ninja -DCMAKE_C_COMPILER=gcc -DCMAKE_CXX_COMPILER=g++ -DLLVM_ENABLE_PROJECTS="clang;lld;libc" -DCMAKE_BUILD_TYPE=Release -DLLVM_VERSION_SUFFIX="_p2pool" ../llvm
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

HEADERS_FILE=linux-$LINUX_HEADERS_VERSION.tar.xz

curl -L -O https://www.kernel.org/pub/linux/kernel/v6.x/$HEADERS_FILE

HEADERS_FILE_SHA256="$(sha256sum $HEADERS_FILE | awk '{ print $1 }')"

if [ $HEADERS_FILE_SHA256 != $HEADERS_SHA256 ]; then
    echo "Error: SHA256 sum does not match for $HEADERS_FILE - expected $HEADERS_SHA256, got $HEADERS_FILE_SHA256"
    exit 1
fi

tar xf linux-$LINUX_HEADERS_VERSION.tar.xz
cd linux-$LINUX_HEADERS_VERSION
make ARCH=arm64 INSTALL_HDR_PATH=/usr/local/aarch64-linux-gnu headers_install

echo "Install GCC for aarch64-linux-gnu"

cd /root

mkdir gcc_build_aarch64 && cd gcc_build_aarch64
../gcc/configure --target=aarch64-linux-gnu --enable-languages=c,c++ --disable-multilib
make -j$(nproc) all-gcc
make install-gcc

echo "Install glibc for aarch64-linux-gnu"

cd /root

GLIBC_FILE=glibc-$GLIBC_VERSION.tar.xz

curl -L -O https://ftpmirror.gnu.org/glibc/$GLIBC_FILE

GLIBC_FILE_SHA256="$(sha256sum $GLIBC_FILE | awk '{ print $1 }')"

if [ $GLIBC_FILE_SHA256 != $GLIBC_SHA256 ]; then
    echo "Error: SHA256 sum does not match for $GLIBC_FILE - expected $GLIBC_SHA256, got $GLIBC_FILE_SHA256"
    exit 1
fi

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
../gcc/configure --target=riscv64-linux-gnu --enable-languages=c,c++ --disable-multilib
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

git clone --depth=1 --branch v$MINGW_VERSION https://git.code.sf.net/p/mingw-w64/mingw-w64 mingw-w64-v$MINGW_VERSION
rm -rf mingw-w64-v$MINGW_VERSION/.git

cd mingw-w64-v$MINGW_VERSION/mingw-w64-headers
CFLAGS='-O2' ./configure --host=x86_64-w64-mingw32 --prefix=/usr/local/x86_64-w64-mingw32 --with-default-msvcrt=msvcrt --with-default-win32-winnt=0x0600
make install

echo "Install GCC for x86_64-w64-mingw32"

cd /root

mkdir gcc_build_w64 && cd gcc_build_w64
../gcc/configure --target=x86_64-w64-mingw32 --enable-languages=c,c++ --disable-multilib
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

echo "Install glibc for x86_64-pc-linux-gnu"

cd /root

mkdir glibc_build_x86_64 && cd glibc_build_x86_64
CFLAGS='-O2' ../glibc-$GLIBC_VERSION/configure --build=x86_64-pc-linux-gnu --host=x86_64-pc-linux-gnu --target=x86_64-pc-linux-gnu --prefix=/usr/local/x86_64-pc-linux-gnu --disable-multilib --enable-static-nss
make -j$(nproc) install-bootstrap-headers=yes install-headers
make -j$(nproc) csu/subdir_lib

install csu/crt1.o csu/crti.o csu/crtn.o /usr/local/x86_64-pc-linux-gnu/lib

gcc -nostdlib -nostartfiles -shared -x c /dev/null -o /usr/local/x86_64-pc-linux-gnu/lib/libc.so

make -j$(nproc)
make install

echo "Get osxcross"

cd /root

git clone --branch 2.0-llvm-based https://github.com/tpoechtrager/osxcross
cd osxcross
git checkout cb444e230e815c06202bef1c30eca5d353235a05

echo "Get MacOSX $MACOSX_SDK_VERSION SDK"

cd /root/osxcross/tarballs

MACOSX_SDK_FILE=MacOSX$MACOSX_SDK_VERSION.sdk.tar.xz

curl -L -O https://github.com/joseluisq/macosx-sdks/releases/download/$MACOSX_SDK_VERSION/$MACOSX_SDK_FILE

MACOSX_SDK_FILE_SHA256="$(sha256sum $MACOSX_SDK_FILE | awk '{ print $1 }')"

if [ $MACOSX_SDK_FILE_SHA256 != $MACOSX_SDK_SHA256 ]; then
    echo "Error: SHA256 sum does not match for $MACOSX_SDK_FILE - expected $MACOSX_SDK_SHA256, got $MACOSX_SDK_FILE_SHA256"
    exit 1
fi

echo "Build MacOSX cross compilers"

cd /root/osxcross
TARGET_DIR=/usr/local OSX_VERSION_MIN=10.15 UNATTENDED=1 ./build.sh
./build_compiler_rt.sh

echo "Install FreeBSD $FREEBSD_VERSION SDK"

cd /usr/local

FREEBSD_FILE=base.txz

mkdir cross-freebsd-x86_64 && mkdir cross-freebsd-aarch64
curl -L -Z -o cross-freebsd-x86_64/$FREEBSD_FILE -o cross-freebsd-aarch64/$FREEBSD_FILE https://archive.freebsd.org/old-releases/amd64/$FREEBSD_VERSION-RELEASE/$FREEBSD_FILE https://archive.freebsd.org/old-releases/arm64/$FREEBSD_VERSION-RELEASE/$FREEBSD_FILE

cd /usr/local/cross-freebsd-x86_64

FREEBSD_X86_64_FILE_SHA256="$(sha256sum $FREEBSD_FILE | awk '{ print $1 }')"

if [ $FREEBSD_X86_64_FILE_SHA256 != $FREEBSD_X86_64_SHA256 ]; then
    echo "Error: SHA256 sum does not match for $FREEBSD_FILE - expected $FREEBSD_X86_64_SHA256, got $FREEBSD_X86_64_FILE_SHA256"
    exit 1
fi

tar -xf $FREEBSD_FILE ./lib/ ./usr/lib/ ./usr/include/
rm $FREEBSD_FILE
#find /usr/local/cross-freebsd-x86_64/usr/lib -xtype l|xargs ls -l|grep ' /lib/'|awk '{print "ln -sf /usr/local/cross-freebsd-x86_64"$11 " " $9}'|/bin/sh

cd /usr/local/cross-freebsd-aarch64

FREEBSD_AARCH64_FILE_SHA256="$(sha256sum $FREEBSD_FILE | awk '{ print $1 }')"

if [ $FREEBSD_AARCH64_FILE_SHA256 != $FREEBSD_AARCH64_SHA256 ]; then
    echo "Error: SHA256 sum does not match for $FREEBSD_FILE - expected $FREEBSD_AARCH64_SHA256, got $FREEBSD_AARCH64_FILE_SHA256"
    exit 1
fi

tar -xf $FREEBSD_FILE ./lib/ ./usr/lib/ ./usr/include/
rm $FREEBSD_FILE
#find /usr/local/cross-freebsd-aarch64/usr/lib -xtype l|xargs ls -l|grep ' /lib/'|awk '{print "ln -sf /usr/local/cross-freebsd-aarch64"$11 " " $9}'|/bin/sh

echo "Install xz"

apt-get remove -yq xz-utils

cd /root

git clone --depth=1 --branch v$XZ_VERSION https://github.com/tukaani-project/xz
cd xz
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=clang
make -j$(nproc)

cp -f lzma* /usr/bin
cp -f xz* /usr/bin

echo "Deleting system glibc files to force our glibc"

rm /usr/lib/x86_64-linux-gnu/crt1.o
rm /usr/lib/x86_64-linux-gnu/crti.o
rm /usr/lib/x86_64-linux-gnu/crtn.o
rm /usr/lib/x86_64-linux-gnu/libc.a
