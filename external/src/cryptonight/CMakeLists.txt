# CryptoNight-Turtle-Lite v2 PoW library for Kryptokrona (XKR).
#
# These sources are vendored verbatim from kryptokrona (src/crypto) and
# implement the CryptoNight family hash used for XKR's block v5+ proof-of-work.
# They are built as an isolated static library so p2pool's strict warning/error
# flags do not apply to this third-party C code.

cmake_minimum_required(VERSION 3.10)

project(cryptonight C)

set(CRYPTONIGHT_SOURCES
	slow-hash.c
	aesb.c
	oaes_lib.c
	keccak.c
	hash.c
	blake256.c
	groestl.c
	jh.c
	skein.c
	hash-extra-blake.c
	hash-extra-groestl.c
	hash-extra-jh.c
	hash-extra-skein.c
	xkr_pow.c
)

add_library(cryptonight STATIC ${CRYPTONIGHT_SOURCES})

set_target_properties(cryptonight PROPERTIES C_STANDARD 11)

# Consumers include "xkr_pow.h" from here.
target_include_directories(cryptonight PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

# Kryptokrona builds this code with no special -march on aarch64 and -maes on
# x86_64 (see kryptokrona/CMakeLists.txt). The portable software-AES path is
# correct on every target; -maes is purely a speed-up on x86.
if (NOT MSVC)
	target_compile_options(cryptonight PRIVATE -w)
	if (CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64|i686|i386")
		target_compile_options(cryptonight PRIVATE -maes)
	endif()
endif()
