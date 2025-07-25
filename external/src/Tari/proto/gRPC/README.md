To update the files:

- Build gRPC in `../../../grpc/.build` folder: `cmake .. && make -j$(nproc)`
- Run `../../../grpc/.build/third_party/protobuf/protoc --cpp_out=. --plugin=protoc-gen-grpc=../../../grpc/.build/grpc_cpp_plugin --grpc_out=. --proto_path=../../../grpc/third_party/protobuf/src --proto_path=. *.proto`