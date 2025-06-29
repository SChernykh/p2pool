#!/bin/sh

export DEBIAN_FRONTEND=noninteractive
apt-get update && apt-get upgrade -yq --no-install-recommends
apt-get install -yq --no-install-recommends patch lsb-release wget software-properties-common gnupg p7zip cmake make gcc-aarch64-linux-gnu g++-aarch64-linux-gnu binutils-aarch64-linux-gnu gcc-riscv64-linux-gnu g++-riscv64-linux-gnu binutils-riscv64-linux-gnu g++-mingw-w64-x86-64 gcc-mingw-w64-x86-64 binutils-mingw-w64-x86-64

wget https://apt.llvm.org/llvm.sh
chmod +x llvm.sh
./llvm.sh 20 all
