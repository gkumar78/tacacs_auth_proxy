/*
 *
 * Copyright 2015 gRPC authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <iostream>
#include <memory>
#include <string>

#include <grpcpp/grpcpp.h>
#include <voltha_protos/openolt.grpc.pb.h>

using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;


class ProxyClient {

 public:

  ProxyClient(std::shared_ptr<Channel> channel)
      : stub_(openolt::Openolt::NewStub(channel)) {}


  // Assembles the client's payload, sends it and presents the response back
  // from the server.
    Status DisableOlt(ClientContext* context,
            const openolt::Empty* request,
            openolt::Empty* response) {
        
    // The actual RPC.
    return stub_->DisableOlt(context, *request, response);

    }

 private:
  std::unique_ptr<openolt::Openolt::Stub> stub_;
};
