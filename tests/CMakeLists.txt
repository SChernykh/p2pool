cmake_minimum_required(VERSION 3.5)
project(p2pool_tests)

include(cmake/standard.cmake)

option(STATIC_LIBS "Use locally built libuv and libzmq static libs" OFF)
option(WITH_LTO "Use link-time compiler optimization (if linking fails for you, run cmake with -DWITH_LTO=OFF)" ON)
option(WITH_COVERAGE "Generate code coverage data" OFF)
option(DEV_DEBUG "[Developer only] Compile a debug build" OFF)

if (DEV_DEBUG)
	add_definitions(-DDEV_DEBUG)
endif()

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake")

if (${CMAKE_VERSION} VERSION_GREATER "3.5.2") 
	set_property(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} PROPERTY VS_STARTUP_PROJECT p2pool_tests)
endif()

set(BUILD_GMOCK OFF CACHE BOOL "Builds the googlemock subproject" FORCE)
set(INSTALL_GTEST OFF CACHE BOOL "Enable installation of googletest. (Projects embedding googletest may want to turn this OFF.)" FORCE)

add_subdirectory(googletest)
set(LIBS gtest)

if (CMAKE_CXX_COMPILER_ID MATCHES MSVC)
	include(cmake/msvc_libs.cmake)
endif()

if (STATIC_LIBS AND WIN32 AND (CMAKE_CXX_COMPILER_ID MATCHES Clang))
	set(LIBS ${LIBS} "${CMAKE_SOURCE_DIR}/../build/external/src/RandomX/librandomx.a")
else()
	add_subdirectory(../external/src/RandomX RandomX)
	set(LIBS ${LIBS} randomx)
endif()

add_definitions(-DWITH_RANDOMX)
add_definitions(-DWITH_MERGE_MINING_DONATION)

add_definitions(-DP2POOL_UNIT_TESTS)
add_definitions(-DP2POOL_SIDECHAIN_EXTRA_1=1)

include(cmake/flags.cmake)

set(HEADERS
)

set(SOURCES
	src/block_template_tests.cpp
	src/crypto_tests.cpp
	src/difficulty_type_tests.cpp
	src/hash_tests.cpp
	src/keccak_tests.cpp
	src/merkle_tests.cpp
	src/log_tests.cpp
	src/main.cpp
	src/pool_block_tests.cpp
	src/sha256_tests.cpp
	src/util_tests.cpp
	src/wallet_tests.cpp
	../external/src/crypto/sha256.c
	../external/src/cryptonote/crypto-ops-data.c
	../external/src/cryptonote/crypto-ops.c
	../external/src/hardforks/hardforks.cpp
	../src/block_cache.cpp
	../src/block_template.cpp
	../src/console_commands.cpp
	../src/crypto.cpp
	../src/keccak.cpp
	../src/log.cpp
	../src/memory_leak_debug.cpp
	../src/mempool.cpp
	../src/merkle.cpp
	../src/miner.cpp
	../src/p2p_server.cpp
	../src/p2pool.cpp
	../src/p2pool_api.cpp
	../src/params.cpp
	../src/pool_block.cpp
	../src/pow_hash.cpp
	../src/side_chain.cpp
	../src/stratum_server.cpp
	../src/tcp_server.cpp
	../src/util.cpp
	../src/wallet.cpp
	../src/zmq_reader.cpp
)

if (AMD64)
	set(SOURCES ${SOURCES} ../src/keccak_bmi.cpp)
	if (CMAKE_C_COMPILER_ID MATCHES GNU OR CMAKE_C_COMPILER_ID MATCHES Clang)
		set_source_files_properties(../src/keccak_bmi.cpp PROPERTIES COMPILE_FLAGS "${CMAKE_CXX_FLAGS} -mbmi")
	endif()
endif()

if ((CMAKE_CXX_COMPILER_ID MATCHES MSVC) OR STATIC_BINARY OR STATIC_LIBS)
	set(UV_INCLUDE_DIR ../external/src/libuv/include)
	set(ZMQ_INCLUDE_DIR ../external/src/libzmq/include)
else()
	find_path(UV_INCLUDE_DIR NAMES uv.h PATH_SUFFIXES "include")
	find_path(ZMQ_INCLUDE_DIR NAMES zmq.h PATH_SUFFIXES "include")
endif()

include_directories(../src)
include_directories(../external/src)
include_directories(../external/src/crypto)
include_directories(../external/src/cryptonote)
include_directories(${UV_INCLUDE_DIR})
include_directories(../external/src/cppzmq)
include_directories(${ZMQ_INCLUDE_DIR})
include_directories(../external/src/protobuf-c)
include_directories(../external/src/RandomX/src)
include_directories(../external/src/rapidjson/include)
include_directories(../external/src/robin-hood-hashing/src/include)
include_directories(src)
include_directories(googletest/googletest/include)

if (WIN32)
	set(LIBS ${LIBS} ws2_32 iphlpapi userenv psapi dnsapi dbghelp)
	if ((CMAKE_CXX_COMPILER_ID MATCHES GNU) OR (CMAKE_CXX_COMPILER_ID MATCHES Clang))
		set(LIBS ${LIBS} bcrypt)
	endif()
elseif (NOT APPLE)
	set(LIBS ${LIBS} pthread)
endif()

if (STATIC_LIBS)
	set(ZMQ_LIBRARY "${CMAKE_SOURCE_DIR}/../external/src/libzmq/build/lib/libzmq.a")
	set(ZMQ_LIBRARY_DEBUG "${CMAKE_SOURCE_DIR}/../external/src/libzmq/build/lib/libzmq.a")
	set(UV_LIBRARY_DEBUG "${CMAKE_SOURCE_DIR}/../external/src/libuv/build/libuv.a")
	set(UV_LIBRARY "${CMAKE_SOURCE_DIR}/../external/src/libuv/build/libuv.a")
else()
	if (CMAKE_CXX_COMPILER_ID MATCHES MSVC)
	elseif (CMAKE_CXX_COMPILER_ID MATCHES GNU OR CMAKE_CXX_COMPILER_ID MATCHES Clang)
		find_library(ZMQ_LIBRARY_DEBUG NAMES zmq libzmq.a)
		find_library(ZMQ_LIBRARY NAMES zmq libzmq.a)
		find_library(UV_LIBRARY_DEBUG NAMES uv libuv.a)
		find_library(UV_LIBRARY NAMES uv libuv.a)
		find_library(SODIUM_LIBRARY sodium)
	endif()

	if (SODIUM_LIBRARY)
		set(LIBS ${LIBS} ${SODIUM_LIBRARY})
	endif()
endif()

find_library(PGM_LIBRARY pgm)
find_library(NORM_LIBRARY norm)

if (PGM_LIBRARY)
	set(LIBS ${LIBS} ${PGM_LIBRARY})
endif()

if (NORM_LIBRARY)
	set(LIBS ${LIBS} ${NORM_LIBRARY})
endif()

if(APPLE)
	find_library(FOUNDATION_LIB Foundation)
	find_library(CORE_FOUNDATION_LIB CoreFoundation)
	find_library(SYSTEM_CONFIGURATION_LIB SystemConfiguration)
	set(LIBS ${LIBS} ${FOUNDATION_LIB} ${CORE_FOUNDATION_LIB} ${SYSTEM_CONFIGURATION_LIB})
endif()

add_definitions(/DZMQ_STATIC /DP2POOL_LOG_DISABLE)

include(CheckCXXSourceCompiles)

check_cxx_source_compiles("int main(){ return __builtin_clzll(1);}" HAVE_BUILTIN_CLZLL)
check_cxx_source_compiles("#include <intrin.h>\n#pragma intrinsic(_BitScanReverse64)\nint main(){unsigned long r;_BitScanReverse64(&r,1);return r;}" HAVE_BITSCANREVERSE64)

if (HAVE_BUILTIN_CLZLL)
	add_definitions(/DHAVE_BUILTIN_CLZLL)
endif()

if (HAVE_BITSCANREVERSE64)
	add_definitions(/DHAVE_BITSCANREVERSE64)
endif()

add_definitions("-DRAPIDJSON_PARSE_DEFAULT_FLAGS=kParseTrailingCommasFlag")

add_executable(${CMAKE_PROJECT_NAME} ${HEADERS} ${SOURCES})
target_link_libraries(${CMAKE_PROJECT_NAME} debug ${ZMQ_LIBRARY_DEBUG} debug ${UV_LIBRARY_DEBUG} optimized ${ZMQ_LIBRARY} optimized ${UV_LIBRARY} ${LIBS})
add_custom_command(TARGET ${CMAKE_PROJECT_NAME} POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy_if_different "${CMAKE_SOURCE_DIR}/src/crypto_tests.txt" $<TARGET_FILE_DIR:${CMAKE_PROJECT_NAME}>)
add_custom_command(TARGET ${CMAKE_PROJECT_NAME} POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy_if_different "${CMAKE_SOURCE_DIR}/src/block.dat" $<TARGET_FILE_DIR:${CMAKE_PROJECT_NAME}>)
add_custom_command(TARGET ${CMAKE_PROJECT_NAME} POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy_if_different "${CMAKE_SOURCE_DIR}/src/sidechain_dump.dat.xz" $<TARGET_FILE_DIR:${CMAKE_PROJECT_NAME}>)
add_custom_command(TARGET ${CMAKE_PROJECT_NAME} POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy_if_different "${CMAKE_SOURCE_DIR}/src/sidechain_dump_mini.dat.xz" $<TARGET_FILE_DIR:${CMAKE_PROJECT_NAME}>)
add_custom_command(TARGET ${CMAKE_PROJECT_NAME} POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy_if_different "${CMAKE_SOURCE_DIR}/src/sidechain_dump_nano.dat.xz" $<TARGET_FILE_DIR:${CMAKE_PROJECT_NAME}>)
