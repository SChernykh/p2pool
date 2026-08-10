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

	# IMPORTANT: the vendored cn_slow_hash has a strict-aliasing (type-punning)
	# undefined-behavior bug that the compiler miscompiles under -fstrict-aliasing
	# (implied by -O2 and up), producing a WRONG hash for ~1 in 4 blobs. Symptom:
	# p2pool rejects that fraction of perfectly valid shares/blocks as "invalid PoW"
	# and bans the peers that sent them.
	#
	# Capping at -O2 alone is NOT enough: on x86 the miscompile only shows at -O3,
	# but on aarch64 (Apple Silicon) it already fires at -O2/-Os — the exact flags
	# the macOS-arm64 CI build uses — so an arm64 node rejects valid blocks from its
	# correct x86 peers. Fix the actual UB instead of chasing -O levels:
	# -fno-strict-aliasing makes the type-punning defined and produces bit-identical
	# hashes to the daemon/xmrig on every target (this is how Monero/xmrig build the
	# same code). Keep -O2 for validation throughput.
	if (CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64")
		# On aarch64 (Apple Silicon) the UB miscompiles even at -O2 (with or without
		# -fno-strict-aliasing) — verified: it computes a wrong hash that disagrees
		# with the daemon/xmrig and the -O0 golden vectors, so an arm64 node rejects
		# valid blocks from its correct peers. -O0 is the level the C/Go golden
		# vectors were validated at. p2pool only hashes for validation (not mining),
		# so this is not a throughput concern.
		target_compile_options(cryptonight PRIVATE -O0 -fno-strict-aliasing)
	else()
		target_compile_options(cryptonight PRIVATE -O2 -fno-strict-aliasing)
	endif()
else()
	# Same optimization miscompile on MSVC: a Release (/O2) Windows build computes
	# the wrong hash / side-chain id for some blobs, so a Windows p2pool NODE
	# rejects valid blocks from its (correct) Linux peers, bans them, and ends up
	# with 0 peers. Disable optimization for this one library on MSVC so the hash
	# is bit-identical to the daemon and the Linux nodes. Validation is not a
	# throughput bottleneck, so /Od is fine. (This later /Od overrides the /O2 that
	# the Release configuration adds.)
	target_compile_options(cryptonight PRIVATE /w /Od)
endif()
