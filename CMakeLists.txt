cmake_minimum_required(VERSION 2.8.12)
project(p2pool)

option(STATIC_BINARY "Build static binary" OFF)
option(STATIC_LIBS "Link libuv and libzmq statically" OFF)
option(WITH_RANDOMX "Include the RandomX library in the build. If this is turned off, p2pool will rely on monerod for verifying RandomX hashes" ON)
option(WITH_LTO "Use link-time compiler optimization (if linking fails for you, run cmake with -DWITH_LTO=OFF)" ON)
option(WITH_UPNP "Include UPnP support. If this is turned off, p2pool will not be able to configure port forwarding on UPnP-enabled routers." ON)

option(DEV_TEST_SYNC "[Developer only] Sync test, stop p2pool after sync is complete" OFF)
option(DEV_WITH_TSAN "[Developer only] Compile with thread sanitizer" OFF)
option(DEV_WITH_MSAN "[Developer only] Compile with memory sanitizer" OFF)
option(DEV_WITH_UBSAN "[Developer only] Compile with undefined behavior sanitizer" OFF)
option(DEV_WITH_ASAN "[Developer only] Compile with address sanitizer" OFF)
option(DEV_CLANG_TIDY "[Developer only] Compile for clang-tidy" OFF)
option(DEV_TRACK_MEMORY "[Developer only] Track memory allocations" OFF)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake")

if (${CMAKE_VERSION} VERSION_GREATER "3.5.2") 
	set_property(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} PROPERTY VS_STARTUP_PROJECT p2pool)
endif()

if (WITH_RANDOMX)
	add_definitions(-DWITH_RANDOMX)
	add_subdirectory(external/src/RandomX)
	set(LIBS ${LIBS} randomx)
endif()

if (WITH_UPNP)
	add_definitions(-DWITH_UPNP)
	add_subdirectory(external/src/miniupnp/miniupnpc)
	set(LIBS ${LIBS} libminiupnpc-static)
endif()

if (DEV_TEST_SYNC)
	add_definitions(-DDEV_TEST_SYNC)
endif()

if (DEV_WITH_TSAN)
	add_definitions(-DDEV_WITH_TSAN)
endif()

if (DEV_WITH_MSAN)
	add_definitions(-DDEV_WITH_MSAN)
endif()

if (DEV_WITH_UBSAN)
	add_definitions(-DDEV_WITH_UBSAN)
endif()

if (DEV_WITH_ASAN)
	add_definitions(-DDEV_WITH_ASAN)
endif()

if (DEV_CLANG_TIDY)
	add_definitions(-DDEV_CLANG_TIDY)
endif()

if (DEV_TRACK_MEMORY)
	add_definitions(-DDEV_TRACK_MEMORY)
endif()

include(cmake/flags.cmake)

set(HEADERS
	external/src/cryptonote/crypto-ops.h
	external/src/hardforks/hardforks.h
	src/block_cache.h
	src/block_template.h
	src/common.h
	src/console_commands.h
	src/crypto.h
	src/json_parsers.h
	src/json_rpc_request.h
	src/keccak.h
	src/log.h
	src/mempool.h
	src/p2p_server.h
	src/p2pool.h
	src/p2pool_api.h
	src/params.h
	src/pool_block.h
	src/pool_block_parser.inl
	src/pow_hash.h
	src/side_chain.h
	src/stratum_server.h
	src/tcp_server.h
	src/util.h
	src/uv_util.h
	src/wallet.h
	src/zmq_reader.h
)

set(SOURCES
	external/src/cryptonote/crypto-ops-data.c
	external/src/cryptonote/crypto-ops.c
	external/src/hardforks/hardforks.cpp
	src/block_cache.cpp
	src/block_template.cpp
	src/console_commands.cpp
	src/crypto.cpp
	src/json_rpc_request.cpp
	src/keccak.cpp
	src/log.cpp
	src/main.cpp
	src/memory_leak_debug.cpp
	src/mempool.cpp
	src/p2p_server.cpp
	src/p2pool.cpp
	src/p2pool_api.cpp
	src/params.cpp
	src/pool_block.cpp
	src/pow_hash.cpp
	src/side_chain.cpp
	src/stratum_server.cpp
	src/tcp_server.cpp
	src/util.cpp
	src/wallet.cpp
	src/zmq_reader.cpp
)

if (WITH_RANDOMX)
	set(HEADERS ${HEADERS} src/miner.h)
	set(SOURCES ${SOURCES} src/miner.cpp)
endif()

if (NOT ((CMAKE_CXX_COMPILER_ID MATCHES MSVC) OR STATIC_BINARY OR STATIC_LIBS))
	include(FindCURL)
endif()

if (CURL_INCLUDE_DIRS)
	include_directories(${CURL_INCLUDE_DIRS})
else()
	include_directories(external/src/curl/include)
endif()

if ((CMAKE_CXX_COMPILER_ID MATCHES MSVC) OR STATIC_BINARY OR STATIC_LIBS)
	set(UV_INCLUDE_DIR external/src/libuv/include)
	set(ZMQ_INCLUDE_DIR external/src/libzmq/include)
else()
	find_path(UV_INCLUDE_DIR NAMES uv.h PATH_SUFFIXES "include")
	find_path(ZMQ_INCLUDE_DIR NAMES zmq.h PATH_SUFFIXES "include")
endif()

include_directories(src)
include_directories(external/src)
include_directories(external/src/cryptonote)
include_directories(${UV_INCLUDE_DIR})
include_directories(external/src/cppzmq)
include_directories(${ZMQ_INCLUDE_DIR})
if (WITH_RANDOMX)
	include_directories(external/src/RandomX/src)
endif()
include_directories(external/src/rapidjson/include)
include_directories(external/src/robin-hood-hashing/src/include)
if (WITH_UPNP)
	include_directories(external/src/miniupnp/miniupnpc/include)
endif()

if (WIN32)
	set(LIBS ${LIBS} ws2_32 iphlpapi userenv psapi dnsapi dbghelp)
	if (CMAKE_CXX_COMPILER_ID MATCHES GNU)
		set(LIBS ${LIBS} bcrypt)
	endif()
	add_definitions(-DCURL_STATICLIB)
elseif (CMAKE_SYSTEM_NAME STREQUAL FreeBSD)
	set(LIBS ${LIBS} pthread)
elseif (NOT APPLE)
	set(LIBS ${LIBS} pthread)
endif()

if (CMAKE_CXX_COMPILER_ID MATCHES MSVC)
	find_library(ZMQ_LIBRARY_DEBUG NAMES libzmq-v142-mt-sgd-4_3_5 PATHS "external/lib/libzmq/Debug")
	find_library(ZMQ_LIBRARY NAMES libzmq-v142-mt-s-4_3_5 PATHS "external/lib/libzmq/Release")
	find_library(UV_LIBRARY_DEBUG NAMES libuv PATHS "external/lib/libuv/Debug")
	find_library(UV_LIBRARY NAMES libuv PATHS "external/lib/libuv/Release")
	find_library(CURL_LIBRARY_DEBUG NAMES libcurl-d PATHS "external/lib/libcurl/Debug")
	find_library(CURL_LIBRARY NAMES libcurl PATHS "external/lib/libcurl/Release")
	add_definitions(-D_DISABLE_VECTOR_ANNOTATION)
	add_definitions(-D_DISABLE_STRING_ANNOTATION)
elseif (CMAKE_CXX_COMPILER_ID MATCHES GNU OR CMAKE_CXX_COMPILER_ID MATCHES Clang)
	find_library(ZMQ_LIBRARY_DEBUG NAMES zmq libzmq.a)
	find_library(ZMQ_LIBRARY NAMES zmq libzmq.a)
	find_library(UV_LIBRARY_DEBUG NAMES uv libuv.a)
	find_library(UV_LIBRARY NAMES uv libuv.a)
	if (WIN32)
		find_library(CURL_LIBRARY_DEBUG NAMES libcurl.a PATHS "external/src/curl/lib/.libs" NO_DEFAULT_PATH)
		find_library(CURL_LIBRARY NAMES libcurl.a PATHS "external/src/curl/lib/.libs" NO_DEFAULT_PATH)
	else()
		if (CURL_LIBRARIES)
			set(CURL_LIBRARY_DEBUG ${CURL_LIBRARIES})
			set(CURL_LIBRARY ${CURL_LIBRARIES})
		else()
			find_library(CURL_LIBRARY_DEBUG NAMES curl)
			find_library(CURL_LIBRARY NAMES curl)
		endif()
	endif()
	find_library(SODIUM_LIBRARY sodium)
endif()

find_library(PGM_LIBRARY pgm)
find_library(NORM_LIBRARY norm)

if (PGM_LIBRARY)
	set(LIBS ${LIBS} ${PGM_LIBRARY})
endif()

if (NORM_LIBRARY)
	set(LIBS ${LIBS} ${NORM_LIBRARY})
endif()

if (SODIUM_LIBRARY)
	set(LIBS ${LIBS} ${SODIUM_LIBRARY})
endif()

if(APPLE)
	find_library(FOUNDATION_LIB Foundation)
	find_library(CORE_FOUNDATION_LIB CoreFoundation)
	find_library(SYSTEM_CONFIGURATION_LIB SystemConfiguration)
	set(LIBS ${LIBS} ${FOUNDATION_LIB} ${CORE_FOUNDATION_LIB} ${SYSTEM_CONFIGURATION_LIB})
endif()

add_definitions(/DZMQ_STATIC)

include(CheckCXXSourceCompiles)

check_cxx_source_compiles("int main(){ return __builtin_clzll(1);}" HAVE_BUILTIN_CLZLL)
check_cxx_source_compiles("#include <intrin.h>\n#pragma intrinsic(_BitScanReverse64)\nint main(){unsigned long r;_BitScanReverse64(&r,1);return r;}" HAVE_BITSCANREVERSE64)
check_cxx_source_compiles("#include <sched.h>\nint main(){sched_param param;return sched_setscheduler(0, SCHED_IDLE, &param);}" HAVE_SCHED)

include(CheckCSourceCompiles)

set(CMAKE_REQUIRED_LIBRARIES "resolv")

check_c_source_compiles("int main() { return 0; }" HAVE_RESOLV_LIB)

if (NOT HAVE_RESOLV_LIB)
	set(CMAKE_REQUIRED_LIBRARIES)
endif()

check_c_source_compiles("
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <stdio.h>
#include <memory.h>

int main(int argc, char* argv[])
{
	if (argc < 2) {
		return 1;
	}

	res_init();

	uint8_t answer[4096];
	const int anslen = res_query(argv[1], ns_c_in, ns_t_txt, answer, sizeof(answer));

	if (anslen > (int) sizeof(answer)) {
		return 1;
	}

	ns_msg handle;
	ns_initparse(answer, anslen, &handle);

	for (int rrnum = 0, n = ns_msg_count(handle, ns_s_an); rrnum < n; ++rrnum) {
		ns_rr rr;
		if ((ns_parserr(&handle, ns_s_an, rrnum, &rr) == 0) && (ns_rr_type(rr) == ns_t_txt)) {
			for (const uint8_t* data = ns_rr_rdata(rr), *e = data + ns_rr_rdlen(rr); data < e;) {
				const int k = *(data++);
				if (k && (data + k <= e)) {
					char buf[256];
					memcpy(buf, data, k);
					buf[k] = 0;
					puts(buf);
				}
				data += k;
			}
		}
	}

	return 0;
}" HAVE_RES_QUERY)

set(CMAKE_REQUIRED_LIBRARIES)

if (HAVE_BUILTIN_CLZLL)
	add_definitions(/DHAVE_BUILTIN_CLZLL)
endif()

if (HAVE_BITSCANREVERSE64)
	add_definitions(/DHAVE_BITSCANREVERSE64)
endif()

if (HAVE_SCHED)
	add_definitions(/DHAVE_SCHED)
endif()

if (HAVE_RES_QUERY)
	add_definitions(/DHAVE_RES_QUERY)
	if (HAVE_RESOLV_LIB)
		set(LIBS ${LIBS} resolv)
	endif()
endif()

add_definitions("-DRAPIDJSON_PARSE_DEFAULT_FLAGS=kParseTrailingCommasFlag")

add_executable(${CMAKE_PROJECT_NAME} ${HEADERS} ${SOURCES})

if (STATIC_BINARY OR STATIC_LIBS)
	if (NOT (DEV_WITH_TSAN OR DEV_WITH_MSAN OR DEV_WITH_UBSAN OR DEV_WITH_ASAN))
		if (WIN32)
			add_custom_command(TARGET ${CMAKE_PROJECT_NAME} POST_BUILD COMMAND ${CMAKE_STRIP} "${CMAKE_PROJECT_NAME}.exe")
		else()
			add_custom_command(TARGET ${CMAKE_PROJECT_NAME} POST_BUILD COMMAND ${CMAKE_STRIP} ${CMAKE_PROJECT_NAME})
		endif()
	endif()

	if (WITH_RANDOMX)
		set(STATIC_LIBS randomx)
	endif()

	if (WITH_UPNP)
		set(STATIC_LIBS ${STATIC_LIBS} libminiupnpc-static)
	endif()

	if (WIN32)
		set(STATIC_LIBS ${STATIC_LIBS} ws2_32 iphlpapi userenv psapi dnsapi dbghelp)
		if (CMAKE_CXX_COMPILER_ID MATCHES GNU)
			set(STATIC_LIBS ${STATIC_LIBS} bcrypt)
		endif()
	elseif (CMAKE_SYSTEM_NAME STREQUAL FreeBSD)
		set(STATIC_LIBS ${STATIC_LIBS} pthread)
	elseif (APPLE)
		find_library(FOUNDATION_LIB Foundation)
		find_library(CORE_FOUNDATION_LIB CoreFoundation)
		find_library(SYSTEM_CONFIGURATION_LIB SystemConfiguration)
		set(STATIC_LIBS ${STATIC_LIBS} ${FOUNDATION_LIB} ${CORE_FOUNDATION_LIB} ${SYSTEM_CONFIGURATION_LIB})
	else()
		set(STATIC_LIBS ${STATIC_LIBS} pthread)
	endif()

	if (HAVE_RES_QUERY AND HAVE_RESOLV_LIB)
		set(STATIC_LIBS ${STATIC_LIBS} resolv)
	endif()

	target_link_libraries(${CMAKE_PROJECT_NAME}
		"${CMAKE_SOURCE_DIR}/external/src/libzmq/build/lib/libzmq.a"
		"${CMAKE_SOURCE_DIR}/external/src/libuv/build/libuv.a"
		"${CMAKE_SOURCE_DIR}/external/src/curl/lib/.libs/libcurl.a"
		${STATIC_LIBS}
	)
else()
	target_link_libraries(${CMAKE_PROJECT_NAME} debug ${ZMQ_LIBRARY_DEBUG} debug ${UV_LIBRARY_DEBUG} debug ${CURL_LIBRARY_DEBUG} optimized ${ZMQ_LIBRARY} optimized ${UV_LIBRARY} optimized ${CURL_LIBRARY} ${LIBS})
endif()
