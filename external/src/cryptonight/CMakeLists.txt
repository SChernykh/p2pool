# CryptoNight-Turtle-Lite v2 PoW library for Kryptokrona (XKR).
#
# These sources are vendored verbatim from kryptokrona (src/crypto) and
# implement the CryptoNight family hash used for XKR's block v5+ proof-of-work.
# They are built as an isolated static library so p2pool's strict warning/error
# flags do not apply to this third-party C code.

cmake_minimum_required(VERSION 3.10)

project(cryptonight C)

# Match p2pool's static CRT (/MT). This library is a separate CMake project and
# otherwise inherits CMake's default dynamic CRT (/MD), which mismatches
# p2pool.exe at link time on MSVC (LNK4098 + unresolved __imp__getpid /
# __imp__ftime64). Rewrite /MD -> /MT (covers /MDd -> /MTd) for all configs.
if (MSVC)
	foreach(flag_var
			CMAKE_C_FLAGS CMAKE_C_FLAGS_DEBUG CMAKE_C_FLAGS_RELEASE
			CMAKE_C_FLAGS_RELWITHDEBINFO CMAKE_C_FLAGS_MINSIZEREL)
		if (${flag_var} MATCHES "/MD")
			string(REGEX REPLACE "/MD" "/MT" ${flag_var} "${${flag_var}}")
		endif()
	endforeach()
endif()

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

# FORCE_USE_HEAP: allocate the CryptoNight scratchpad on the heap (per call)
# instead of as a ~256 KB stack VLA. kryptokrona's own daemon builds this code
# with -DFORCE_USE_HEAP; matching it keeps the hash bit-identical to the daemon
# and avoids a large stack allocation in p2pool's libuv worker threads (which
# run share PoW validation) that can otherwise corrupt the result.
target_compile_definitions(cryptonight PRIVATE FORCE_USE_HEAP)

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
