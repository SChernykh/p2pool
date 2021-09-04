cmake_minimum_required(VERSION 2.8.12)
project(p2pool_tests)

add_subdirectory(googletest)
set(LIBS gtest)

if (CMAKE_CXX_COMPILER_ID MATCHES GNU)
	set(WARNING_FLAGS "")
	set(OPTIMIZATION_FLAGS "-Ofast -s")

	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${WARNING_FLAGS}")
	set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} ${WARNING_FLAGS} ${OPTIMIZATION_FLAGS}")

	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${WARNING_FLAGS}")
	set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} ${WARNING_FLAGS} ${OPTIMIZATION_FLAGS}")

	if (WIN32)
		set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static")
	else()
		if (STATIC_LINUX_BINARY)
			set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static")
		else()
			set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static-libgcc -static-libstdc++")
		endif()
	endif()
elseif (CMAKE_CXX_COMPILER_ID MATCHES MSVC)
	set(WARNING_FLAGS "")
	set(SECURITY_FLAGS "/GS /guard:cf")
	set(OPTIMIZATION_FLAGS "/O2 /Oi /Ob2 /Ot /DNDEBUG /GL")

	set(CMAKE_C_FLAGS_DEBUG "${WARNING_FLAGS} ${SECURITY_FLAGS} /Od /Ob0 /Zi /MTd /fsanitize=address")
	set(CMAKE_CXX_FLAGS_DEBUG "${WARNING_FLAGS} ${SECURITY_FLAGS} /Od /Ob0 /Zi /MTd /fsanitize=address")

	set(CMAKE_C_FLAGS_RELEASE "${WARNING_FLAGS} ${SECURITY_FLAGS} ${OPTIMIZATION_FLAGS} /MT")
	set(CMAKE_CXX_FLAGS_RELEASE "${WARNING_FLAGS} ${SECURITY_FLAGS} ${OPTIMIZATION_FLAGS} /MT")

	set(CMAKE_C_FLAGS_RELWITHDEBINFO "${WARNING_FLAGS} ${SECURITY_FLAGS} /Ob1 /Ot /Zi /MT")
	set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "${WARNING_FLAGS} ${SECURITY_FLAGS} /Ob1 /Ot /Zi /MT")
elseif (CMAKE_CXX_COMPILER_ID MATCHES Clang)
	set(WARNING_FLAGS "")
	set(OPTIMIZATION_FLAGS "-Ofast -funroll-loops -fmerge-all-constants")

	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${WARNING_FLAGS}")
	set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} ${WARNING_FLAGS} ${OPTIMIZATION_FLAGS}")

	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${WARNING_FLAGS}")
	set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} ${WARNING_FLAGS} ${OPTIMIZATION_FLAGS}")
endif()

set(HEADERS
)

set(SOURCES
	src/crypto_tests.cpp
	src/difficulty_type_tests.cpp
	src/keccak_tests.cpp
	src/main.cpp
	src/wallet_tests.cpp
	../external/src/cryptonote/crypto-ops-data.c
	../external/src/cryptonote/crypto-ops.c
	../src/crypto.cpp
	../src/keccak.cpp
	../src/log.cpp
	../src/util.cpp
	../src/wallet.cpp
)

include_directories(../src)
include_directories(../external/src)
include_directories(../external/src/cryptonote)
include_directories(../external/src/libuv/include)
include_directories(../external/src/cppzmq)
include_directories(../external/src/libzmq/include)
include_directories(../external/src/llhttp)
include_directories(../external/src/randomx/src)
include_directories(src)
include_directories(googletest/googletest/include)

if (WIN32)
	set(LIBS ${LIBS} ws2_32 iphlpapi userenv psapi)
elseif (NOT APPLE)
	set(LIBS ${LIBS} pthread gss dl)
endif()

if (CMAKE_CXX_COMPILER_ID MATCHES MSVC)
	find_library(ZMQ_LIBRARY_DEBUG NAMES libzmq-v142-mt-sgd-4_3_5 PATHS "../external/lib/libzmq/Debug")
	find_library(ZMQ_LIBRARY NAMES libzmq-v142-mt-s-4_3_5 PATHS "../external/lib/libzmq/Release")
	find_library(UV_LIBRARY_DEBUG NAMES uv_a PATHS "../external/lib/libuv/Debug")
	find_library(UV_LIBRARY NAMES uv_a PATHS "../external/lib/libuv/Release")
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

add_definitions(/DZMQ_STATIC /DP2POOL_LOG_DISABLE)

add_executable(${CMAKE_PROJECT_NAME} ${HEADERS} ${SOURCES})
target_link_libraries(${CMAKE_PROJECT_NAME} debug ${ZMQ_LIBRARY_DEBUG} debug ${UV_LIBRARY_DEBUG} optimized ${ZMQ_LIBRARY} optimized ${UV_LIBRARY} ${LIBS})
add_custom_command(TARGET ${CMAKE_PROJECT_NAME} POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy_if_different "${CMAKE_SOURCE_DIR}/src/crypto_tests.txt" $<TARGET_FILE_DIR:${CMAKE_PROJECT_NAME}>)
