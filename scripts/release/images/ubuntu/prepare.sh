#!/bin/sh
set -e

# Software versions to install

_7ZIP_VERSION=2600
BINUTILS_VERSION=2_46
CLANG_VERSION=21.1.8
CMAKE_VERSION=4.2.3
FREEBSD_VERSION=12.4
GCC_VERSION=15.2.0
GLIBC_VERSION=2.43
LINUX_HEADERS_VERSION=6.19.3
MACOSX_SDK_VERSION=26.1
OSXCROSS_VERSION=2bc739ebe45db5d72e176d2a4e1c7dd95464e8e2
MAKE_VERSION=4.4.1
MINGW_VERSION=13.0.0
XZ_VERSION=5.8.2
TAR_VERSION=1.35

_7ZIP_SHA256="c74dc4a48492cde43f5fec10d53fb2a66f520e4a62a69d630c44cb22c477edc6"
CMAKE_SHA256="5bb505d5e0cca0480a330f7f27ccf52c2b8b5214c5bba97df08899f5ef650c23"
FREEBSD_AARCH64_SHA256="6c401819bfb93e810c9f9aa670a1e4685f924df5e7e0c9c6397dd6c16c954fa2"
FREEBSD_X86_64_SHA256="581c7edacfd2fca2bdf5791f667402d22fccd8a5e184635e0cac075564d57aa8"
GLIBC_SHA256="d9c86c6b5dbddb43a3e08270c5844fc5177d19442cf5b8df4be7c07cd5fa3831"
HEADERS_SHA256="0e474968adfcbee32916fd01a89d8ccfd1168d8d32569e76a5c664c793198ebe"
MACOSX_SDK_SHA256="beee7212d265a6d2867d0236cc069314b38d5fb3486a6515734e76fa210c784c"
MAKE_SHA256="dd16fb1d67bfab79a72f5e8390735c49e3e8e70b4945a15ab1f81ddb78658fb3"
TAR_SHA256="4d62ff37342ec7aed748535323930c7cf94acf71c3591882b26a7ea50f3edc16"

echo "Install prerequisites"

export DEBIAN_FRONTEND=noninteractive

apt-get update && apt-get upgrade -yq --no-install-recommends
apt-get install -yq --no-install-recommends ca-certificates curl bzip2 flex texinfo bison ninja-build python3 python3-yaml file rsync xz-utils gawk gettext patch git gcc g++

echo "Cloning the P2Pool repository in background"

cd /
git clone --recursive --jobs $(nproc) https://github.com/SChernykh/p2pool &

echo "Download archives"

cd /root

MAKE_NAME=make-$MAKE_VERSION
MAKE_FILE=$MAKE_NAME.tar.gz

_7ZIP_FILE=7z$_7ZIP_VERSION-linux-x64.tar.xz

CMAKE_NAME=cmake-$CMAKE_VERSION-linux-x86_64
CMAKE_FILE=$CMAKE_NAME.tar.gz

HEADERS_FILE=linux-$LINUX_HEADERS_VERSION.tar.xz

GLIBC_FILE=glibc-$GLIBC_VERSION.tar.xz

MACOSX_SDK_FILE=MacOSX$MACOSX_SDK_VERSION.sdk.tar.xz

FREEBSD_FILE=base.txz

TAR_FILE=tar-$TAR_VERSION.tar.xz

mkdir /usr/local/cross-freebsd-x86_64
mkdir /usr/local/cross-freebsd-aarch64

curl -L -Z \
-O https://ftpmirror.gnu.org/make/$MAKE_FILE \
-O https://7-zip.org/a/$_7ZIP_FILE \
-O https://github.com/Kitware/CMake/releases/download/v$CMAKE_VERSION/$CMAKE_FILE \
-O https://www.kernel.org/pub/linux/kernel/v6.x/$HEADERS_FILE \
-O https://ftpmirror.gnu.org/glibc/$GLIBC_FILE \
-O https://github.com/joseluisq/macosx-sdks/releases/download/$MACOSX_SDK_VERSION/$MACOSX_SDK_FILE \
-o /usr/local/cross-freebsd-x86_64/$FREEBSD_FILE https://archive.freebsd.org/old-releases/amd64/$FREEBSD_VERSION-RELEASE/$FREEBSD_FILE \
-o /usr/local/cross-freebsd-aarch64/$FREEBSD_FILE https://archive.freebsd.org/old-releases/arm64/$FREEBSD_VERSION-RELEASE/$FREEBSD_FILE \
-O https://ftpmirror.gnu.org/tar/$TAR_FILE

echo "Verifying checksums"

cd /root

MAKE_FILE_SHA256="$(sha256sum $MAKE_FILE | awk '{ print $1 }')"

if [ $MAKE_FILE_SHA256 != $MAKE_SHA256 ]; then
    echo "Error: SHA256 sum does not match for $MAKE_FILE - expected $MAKE_SHA256, got $MAKE_FILE_SHA256"
    exit 1
fi

_7ZIP_FILE_SHA256="$(sha256sum $_7ZIP_FILE | awk '{ print $1 }')"

if [ $_7ZIP_FILE_SHA256 != $_7ZIP_SHA256 ]; then
    echo "Error: SHA256 sum does not match for $_7ZIP_FILE - expected $_7ZIP_SHA256, got $_7ZIP_FILE_SHA256"
    exit 1
fi

CMAKE_FILE_SHA256="$(sha256sum $CMAKE_FILE | awk '{ print $1 }')"

if [ $CMAKE_FILE_SHA256 != $CMAKE_SHA256 ]; then
    echo "Error: SHA256 sum does not match for $CMAKE_FILE - expected $CMAKE_SHA256, got $CMAKE_FILE_SHA256"
    exit 1
fi

HEADERS_FILE_SHA256="$(sha256sum $HEADERS_FILE | awk '{ print $1 }')"

if [ $HEADERS_FILE_SHA256 != $HEADERS_SHA256 ]; then
    echo "Error: SHA256 sum does not match for $HEADERS_FILE - expected $HEADERS_SHA256, got $HEADERS_FILE_SHA256"
    exit 1
fi

GLIBC_FILE_SHA256="$(sha256sum $GLIBC_FILE | awk '{ print $1 }')"

if [ $GLIBC_FILE_SHA256 != $GLIBC_SHA256 ]; then
    echo "Error: SHA256 sum does not match for $GLIBC_FILE - expected $GLIBC_SHA256, got $GLIBC_FILE_SHA256"
    exit 1
fi

MACOSX_SDK_FILE_SHA256="$(sha256sum $MACOSX_SDK_FILE | awk '{ print $1 }')"

if [ $MACOSX_SDK_FILE_SHA256 != $MACOSX_SDK_SHA256 ]; then
    echo "Error: SHA256 sum does not match for $MACOSX_SDK_FILE - expected $MACOSX_SDK_SHA256, got $MACOSX_SDK_FILE_SHA256"
    exit 1
fi

cd /usr/local/cross-freebsd-x86_64

FREEBSD_X86_64_FILE_SHA256="$(sha256sum $FREEBSD_FILE | awk '{ print $1 }')"

if [ $FREEBSD_X86_64_FILE_SHA256 != $FREEBSD_X86_64_SHA256 ]; then
    echo "Error: SHA256 sum does not match for $FREEBSD_FILE - expected $FREEBSD_X86_64_SHA256, got $FREEBSD_X86_64_FILE_SHA256"
    exit 1
fi

cd /usr/local/cross-freebsd-aarch64

FREEBSD_AARCH64_FILE_SHA256="$(sha256sum $FREEBSD_FILE | awk '{ print $1 }')"

if [ $FREEBSD_AARCH64_FILE_SHA256 != $FREEBSD_AARCH64_SHA256 ]; then
    echo "Error: SHA256 sum does not match for $FREEBSD_FILE - expected $FREEBSD_AARCH64_SHA256, got $FREEBSD_AARCH64_FILE_SHA256"
    exit 1
fi

cd /root

TAR_FILE_SHA256="$(sha256sum $TAR_FILE | awk '{ print $1 }')"

if [ $TAR_FILE_SHA256 != $TAR_SHA256 ]; then
    echo "Error: SHA256 sum does not match for $TAR_FILE - expected $TAR_SHA256, got $TAR_FILE_SHA256"
    exit 1
fi

echo "Cloning repositories"

cd /root

git clone --depth 1 --branch releases/gcc-$GCC_VERSION git://gcc.gnu.org/git/gcc.git
git clone --depth 1 --branch binutils-$BINUTILS_VERSION git://sourceware.org/git/binutils-gdb.git
git clone --depth 1 --branch llvmorg-$CLANG_VERSION https://github.com/llvm/llvm-project.git
git clone --depth=1 --branch v$MINGW_VERSION https://git.code.sf.net/p/mingw-w64/mingw-w64 mingw-w64-v$MINGW_VERSION
git clone --branch 2.0-llvm-based https://github.com/tpoechtrager/osxcross
git clone --depth=1 --branch v$XZ_VERSION https://github.com/tukaani-project/xz

mv /root/$MACOSX_SDK_FILE osxcross/tarballs

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
cp -r $CMAKE_NAME/share/cmake-4.2 /usr/local/share

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
../gcc/configure --target=aarch64-linux-gnu --enable-languages=c,c++ --disable-multilib
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

echo "Build MacOSX cross compilers"

cd /root/osxcross
git checkout ${OSXCROSS_VERSION}

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
cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=clang
make -j$(nproc)

cp -f lzma* /usr/bin
cp -f xz* /usr/bin

echo "Install tar"

cd /root

tar xvf $TAR_FILE
cd tar-$TAR_VERSION
FORCE_UNSAFE_CONFIGURE=1 ./configure
make -j$(nproc)
make install

echo "Deleting system glibc files to force our glibc"

rm /usr/lib/x86_64-linux-gnu/crt1.o
rm /usr/lib/x86_64-linux-gnu/crti.o
rm /usr/lib/x86_64-linux-gnu/crtn.o
rm /usr/lib/x86_64-linux-gnu/libc.a

echo "Deleting temporary files"

cd /root
rm -rf *

echo "All done"
