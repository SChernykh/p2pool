set(protobuf_INSTALL OFF CACHE BOOL "Install protobuf binaries and files")
set(protobuf_BUILD_TESTS OFF CACHE BOOL "Build protobuf tests")
set(protobuf_BUILD_PROTOC_BINARIES OFF CACHE BOOL "Build libprotoc and protoc compiler")
set(protobuf_BUILD_SHARED_LIBS OFF CACHE BOOL "Build protobuf Shared Libraries")

set(utf8_range_ENABLE_TESTS OFF CACHE BOOL "Build test suite")
set(utf8_range_ENABLE_INSTALL OFF CACHE BOOL "Configure installation")

set(RE2_BUILD_TESTING OFF CACHE BOOL "enable testing for RE2")

set(gRPC_BUILD_CODEGEN OFF CACHE BOOL "Build codegen")
set(gRPC_BUILD_GRPC_CPP_PLUGIN OFF CACHE BOOL "Build grpc_cpp_plugin")
set(gRPC_BUILD_GRPC_CSHARP_PLUGIN OFF CACHE BOOL "Build grpc_csharp_plugin")
set(gRPC_BUILD_GRPC_NODE_PLUGIN OFF CACHE BOOL "Build grpc_node_plugin")
set(gRPC_BUILD_GRPC_OBJECTIVE_C_PLUGIN OFF CACHE BOOL "Build grpc_objective_c_plugin")
set(gRPC_BUILD_GRPC_PHP_PLUGIN OFF CACHE BOOL "Build grpc_php_plugin")
set(gRPC_BUILD_GRPC_PYTHON_PLUGIN OFF CACHE BOOL "Build grpc_python_plugin")
set(gRPC_BUILD_GRPC_RUBY_PLUGIN OFF CACHE BOOL "Build grpc_ruby_plugin")

set(gRPC_MSVC_STATIC_RUNTIME ON CACHE BOOL "Link gRPC with static msvc runtime libraries")

set(CARES_STATIC ON CACHE BOOL "Build as a static library")
set(CARES_SHARED OFF CACHE BOOL "Build as a shared library")
set(CARES_INSTALL OFF CACHE BOOL "Create installation targets (chain builders may want to disable this)")
set(CARES_BUILD_TOOLS OFF CACHE BOOL "Build tools")

if ((CMAKE_C_COMPILER_ID MATCHES MSVC) OR (CMAKE_CXX_COMPILER_ID MATCHES MSVC))
	include_directories(external/src/common)
endif()

add_definitions(-DPROTOBUF_ENABLE_DEBUG_LOGGING_MAY_LEAK_PII=0)

add_subdirectory(external/src/grpc)
set(LIBS ${LIBS} grpc grpc++ libprotobuf)

include_directories(external/src/grpc/third_party/abseil-cpp)
include_directories(external/src/grpc/third_party/protobuf/src)
include_directories(external/src/grpc/include)
