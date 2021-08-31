cmake_minimum_required(VERSION 2.8.12)
project(p2pool)

option(STATIC_LINUX_BINARY "Build static Linux binary" OFF)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake")

add_subdirectory(external/src/randomx)
set(LIBS randomx)

include(cmake/flags.cmake)

set(HEADERS
	external/src/cryptonote/crypto-ops.h
	external/src/llhttp/llhttp.h
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
	src/params.h
	src/pool_block.h
	src/pool_block_parser.inl
	src/pow_hash.h
	src/side_chain.h
	src/stratum_server.h
	src/tcp_server.h
	src/tcp_server.inl
	src/util.h
	src/uv_util.h
	src/wallet.h
	src/zmq_reader.h
)

set(SOURCES
	external/src/cryptonote/crypto-ops-data.c
	external/src/cryptonote/crypto-ops.c
	external/src/llhttp/api.c
	external/src/llhttp/http.c
	external/src/llhttp/llhttp.c
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
	src/params.cpp
	src/pool_block.cpp
	src/pow_hash.cpp
	src/side_chain.cpp
	src/stratum_server.cpp
	src/util.cpp
	src/wallet.cpp
	src/zmq_reader.cpp
)

include_directories(src)
include_directories(external/src)
include_directories(external/src/cryptonote)
include_directories(external/src/libuv/include)
include_directories(external/src/cppzmq)
include_directories(external/src/libzmq/include)
include_directories(external/src/llhttp)
include_directories(external/src/randomx/src)

if (WIN32)
	set(LIBS ${LIBS} ws2_32 iphlpapi userenv psapi)
elseif (NOT APPLE)
	set(LIBS ${LIBS} pthread gss dl)
endif()

if (CMAKE_CXX_COMPILER_ID MATCHES MSVC)
	find_library(ZMQ_LIBRARY_DEBUG NAMES libzmq-v142-mt-sgd-4_3_5 PATHS "external/lib/libzmq/Debug")
	find_library(ZMQ_LIBRARY NAMES libzmq-v142-mt-s-4_3_5 PATHS "external/lib/libzmq/Release")
	find_library(UV_LIBRARY_DEBUG NAMES uv_a PATHS "external/lib/libuv/Debug")
	find_library(UV_LIBRARY NAMES uv_a PATHS "external/lib/libuv/Release")
elseif (CMAKE_CXX_COMPILER_ID MATCHES GNU OR CMAKE_CXX_COMPILER_ID MATCHES Clang)
	find_library(ZMQ_LIBRARY_DEBUG NAMES zmq libzmq.a)
	find_library(ZMQ_LIBRARY NAMES zmq libzmq.a)
	find_library(UV_LIBRARY_DEBUG NAMES uv libuv.a)
	find_library(UV_LIBRARY NAMES uv libuv.a)
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

add_definitions(/DZMQ_STATIC)

add_executable(${CMAKE_PROJECT_NAME} ${HEADERS} ${SOURCES})

if (STATIC_LINUX_BINARY)
	add_custom_command(TARGET ${CMAKE_PROJECT_NAME} POST_BUILD COMMAND ${CMAKE_STRIP} ${CMAKE_PROJECT_NAME})

	target_link_libraries(${CMAKE_PROJECT_NAME}
		"${CMAKE_SOURCE_DIR}/external/src/libsodium/src/libsodium/.libs/libsodium.a"
		"${CMAKE_SOURCE_DIR}/external/src/libzmq/build/lib/libzmq.a"
		"${CMAKE_SOURCE_DIR}/external/src/libuv/build/libuv_a.a"
		randomx
		pthread
	)
else()
	target_link_libraries(${CMAKE_PROJECT_NAME} debug ${ZMQ_LIBRARY_DEBUG} debug ${UV_LIBRARY_DEBUG} optimized ${ZMQ_LIBRARY} optimized ${UV_LIBRARY} ${LIBS})
endif()
