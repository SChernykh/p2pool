cmake_minimum_required(VERSION 3.10)
project(Tari_gRPC)

set(HEADERS
	proto/gRPC/base_node.pb.h
	proto/gRPC/block.pb.h
	proto/gRPC/network.pb.h
	proto/gRPC/sidechain_types.pb.h
	proto/gRPC/transaction.pb.h
	proto/gRPC/types.pb.h
	proto/gRPC/base_node.grpc.pb.h
	proto/gRPC/block.grpc.pb.h
	proto/gRPC/network.grpc.pb.h
	proto/gRPC/sidechain_types.grpc.pb.h
	proto/gRPC/transaction.grpc.pb.h
	proto/gRPC/types.grpc.pb.h
	proto.h
)

set(SOURCES
	proto/gRPC/base_node.pb.cc
	proto/gRPC/block.pb.cc
	proto/gRPC/network.pb.cc
	proto/gRPC/sidechain_types.pb.cc
	proto/gRPC/transaction.pb.cc
	proto/gRPC/types.pb.cc
	proto/gRPC/base_node.grpc.pb.cc
	proto/gRPC/block.grpc.pb.cc
	proto/gRPC/network.grpc.pb.cc
	proto/gRPC/sidechain_types.grpc.pb.cc
	proto/gRPC/transaction.grpc.pb.cc
	proto/gRPC/types.grpc.pb.cc
)

include_directories(../grpc/third_party/protobuf/src)
include_directories(../grpc/include)
include_directories(../grpc/third_party/abseil-cpp)

if (CMAKE_CXX_COMPILER_ID MATCHES MSVC)
	set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} /W0 /Zi /Od /Ob0 /MP /MTd")
	set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /W0 /Zi /Od /Ob0 /MP /MTd")
	set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} /W0 /O1 /Ob2 /Oi /Os /Oy /MP /GL /MT /GS /guard:cf")
	set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /W0 /O1 /Ob2 /Oi /Os /Oy /MP /GL /MT /GS /guard:cf")
	set(CMAKE_C_FLAGS_RELWITHDEBINFO "${CMAKE_C_FLAGS_RELWITHDEBINFO} /W0 /Ob1 /Ot /Zi /MP /MT")
	set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "${CMAKE_CXX_FLAGS_RELWITHDEBINFO} /W0 /Ob1 /Ot /Zi /MP /MT")
else()
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Os -w")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Os -w")
endif()

add_library(Tari_gRPC ${HEADERS} ${SOURCES})
