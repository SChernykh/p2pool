#pragma once

#ifdef _MSC_VER
#pragma warning(push, 0)
#endif

#include "proto/gRPC/base_node.pb.h"
#include "proto/gRPC/block.pb.h"
#include "proto/gRPC/network.pb.h"
#include "proto/gRPC/sidechain_types.pb.h"
#include "proto/gRPC/transaction.pb.h"
#include "proto/gRPC/types.pb.h"

#include "proto/gRPC/base_node.grpc.pb.h"
#include "proto/gRPC/block.grpc.pb.h"
#include "proto/gRPC/network.grpc.pb.h"
#include "proto/gRPC/sidechain_types.grpc.pb.h"
#include "proto/gRPC/transaction.grpc.pb.h"
#include "proto/gRPC/types.grpc.pb.h"

#include <grpc/grpc.h>
#include <grpcpp/channel.h>
#include <grpcpp/client_context.h>
#include <grpcpp/create_channel.h>
#include <grpcpp/security/credentials.h>

#ifdef _MSC_VER
#pragma warning(pop)
#endif
