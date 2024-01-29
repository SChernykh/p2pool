cmake_minimum_required(VERSION 3.10)
project(Tari_gRPC)

set(HEADERS
	../protobuf-c/protobuf-c/protobuf-c.h
	proto/gRPC/google/protobuf/timestamp.pb-c.h
	proto/gRPC/base_node.pb-c.h
	proto/gRPC/block.pb-c.h
	proto/gRPC/network.pb-c.h
	proto/gRPC/sidechain_types.pb-c.h
	proto/gRPC/transaction.pb-c.h
	proto/gRPC/types.pb-c.h
	proto.h
)

set(SOURCES
	../protobuf-c/protobuf-c/protobuf-c.c
	proto/gRPC/google/protobuf/timestamp.pb-c.c
	proto/gRPC/base_node.pb-c.c
	proto/gRPC/block.pb-c.c
	proto/gRPC/network.pb-c.c
	proto/gRPC/sidechain_types.pb-c.c
	proto/gRPC/transaction.pb-c.c
	proto/gRPC/types.pb-c.c
)

include_directories(../protobuf-c)

set(DISABLE_WARNINGS ON)

include(../../../cmake/flags.cmake)

add_library(Tari_gRPC ${HEADERS} ${SOURCES})
