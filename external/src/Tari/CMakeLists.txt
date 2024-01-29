cmake_minimum_required(VERSION 3.10)
project(Tari_gRPC)

set(HEADERS
	proto/gRPC/base_node.pb.h
	proto/gRPC/block.pb.h
	proto/gRPC/network.pb.h
	proto/gRPC/sidechain_types.pb.h
	proto/gRPC/transaction.pb.h
	proto/gRPC/types.pb.h
	proto.h
)

set(SOURCES
	proto/gRPC/base_node.pb.cc
	proto/gRPC/block.pb.cc
	proto/gRPC/network.pb.cc
	proto/gRPC/sidechain_types.pb.cc
	proto/gRPC/transaction.pb.cc
	proto/gRPC/types.pb.cc
)

include_directories(../protobuf/src)
include_directories(../protobuf/third_party/abseil-cpp)

set(DISABLE_WARNINGS ON)

include(../../../cmake/flags.cmake)

add_library(Tari_gRPC ${HEADERS} ${SOURCES})
