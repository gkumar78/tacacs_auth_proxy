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

using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;


class ProxyClient {

 public:

  ProxyClient(std::shared_ptr<Channel> channel)
      : stub_(NewStub(channel)) {}


  // Assembles the client's payload, sends it and presents the response back
  // from the server.
    Status DisableOLT(ClientContext* context,
            const openolt::Empty* request,
            openolt::Empty* response) {
        
    // The actual RPC.
    Status status = stub_->DisableOLT(context, request, response);

    // Act upon its status.
    if (status.ok()) {
      return Status::OK;
    } else {
      std::cout << status.error_code() << ": " << status.error_message()
                << std::endl;
      return Status(grpc::,status.error_message());  //Need to  write ihe error_code
    }
  }

 Status ReenableOlt(ClientContext* context,
            const openolt::Empty* request,
            openolt::Empty* response) {

    // The actual RPC.
    Status status = stub_->ReenableOlt(context, request, response);

    // Act upon its status.
    if (status.ok()) {
      return Status::OK;
    } else {
      std::cout << status.error_code() << ": " << status.error_message()
                << std::endl;
      return Status(grpc::,status.error_message());  //Need to error the error_code
    }
  }
 Status ActivateOnu(
            ServerContext* context,
            const openolt::Onu* request,
            openolt::Empty* response) {

    // The actual RPC.
    Status status = stub_->ActivateOnu(context, request, response);

    // Act upon its status.
    if (status.ok()) {
      return Status::OK;
    } else {
      std::cout << status.error_code() << ": " << status.error_message()
                << std::endl;
      return Status(grpc::,status.error_message());  //Need to error the error_code
    }
  }
 Status DeactivateOnu(
            ServerContext* context,
            const openolt::Onu* request,
            openolt::Empty* response) {

    // The actual RPC.
    Status status = stub_->DeactivateOnu(context, request, response);

    // Act upon its status.
    if (status.ok()) {
      return Status::OK;
    } else {
      std::cout << status.error_code() << ": " << status.error_message()
                << std::endl;
      return Status(grpc::,status.error_message());  //Need to error the error_code
    }
  }
Status DeleteOnu(
            ServerContext* context,
            const openolt::Onu* request,
            openolt::Empty* response) {

    // The actual RPC.
    Status status = stub_->DeleteOnu(context, request, response);

    // Act upon its status.
    if (status.ok()) {
      return Status::OK;
    } else {
      std::cout << status.error_code() << ": " << status.error_message()
                << std::endl;
      return Status(grpc::,status.error_message());  //Need to error the error_code
    }
  }
Status OmciMsgOut(
            ServerContext* context,
            const openolt::OmciMsg* request,
            openolt::Empty* response) {

    // The actual RPC.
    Status status = stub_->OmciMsgOut(context, request, response);

    // Act upon its status.
    if (status.ok()) {
      return Status::OK;
    } else {
      std::cout << status.error_code() << ": " << status.error_message()
                << std::endl;
      return Status(grpc::,status.error_message());  //Need to error the error_code
    }
  }
 Status OnuPacketOut(
            ServerContext* context,
            const openolt::OnuPacket* request,
            openolt::Empty* response) {

    // The actual RPC.
    Status status = stub_->OnuPacketOut(context, request, response);

    // Act upon its status.
    if (status.ok()) {
      return Status::OK;
    } else {
      std::cout << status.error_code() << ": " << status.error_message()
                << std::endl;
      return Status(grpc::,status.error_message());  //Need to error the error_code
    }
  }
 Status UplinkPacketOut(
            ServerContext* context,
            const openolt::UplinkPacket* request,
            openolt::Empty* response) {

    // The actual RPC.
    Status status = stub_->UplinkPacketOut(context, request, response);

    // Act upon its status.
    if (status.ok()) {
      return Status::OK;
    } else {
      std::cout << status.error_code() << ": " << status.error_message()
                << std::endl;
      return Status(grpc::,status.error_message());  //Need to error the error_code
    }
  }
Status FlowAdd(
            ServerContext* context,
            const openolt::Flow* request,
            openolt::Empty* response){

    // The actual RPC.
    Status status = stub_->FlowAdd(context, request, response);

    // Act upon its status.
    if (status.ok()) {
      return Status::OK;
    } else {
      std::cout << status.error_code() << ": " << status.error_message()
                << std::endl;
      return Status(grpc::,status.error_message());  //Need to error the error_code
    }
  }
Status FlowRemove(
            ServerContext* context,
            const openolt::Flow* request,
            openolt::Empty* response) {

    // The actual RPC.
    Status status = stub_->FlowRemove(context, request, response);

    // Act upon its status.
    if (status.ok()) {
      return Status::OK;
    } else {
      std::cout << status.error_code() << ": " << status.error_message()
                << std::endl;
      return Status(grpc::,status.error_message());  //Need to error the error_code
    }
  }
Status EnableIndication(
            ServerContext* context,
            const ::openolt::Empty* request,
            ServerWriter<openolt::Indication>* writer) {

    // The actual RPC.
    Status status = stub_->EnableIndication(context, request, response);

    // Act upon its status.
    if (status.ok()) {
      return Status::OK;
    } else {
      std::cout << status.error_code() << ": " << status.error_message()
                << std::endl;
      return Status(grpc::,status.error_message());  //Need to error the error_code
    }
  }
   Status HeartbeatCheck(
            ServerContext* context,
            const openolt::Empty* request,
            openolt::Heartbeat* response){

    // The actual RPC.
    Status status = stub_->HeartbeatCheck(context, request, response);

    // Act upon its status.
    if (status.ok()) {
      return Status::OK;
    } else {
      std::cout << status.error_code() << ": " << status.error_message()
                << std::endl;
      return Status(grpc::,status.error_message());  //Need to error the error_code
    }
  }
 Status EnablePonIf(
            ServerContext* context,
            const openolt::Interface* request,
            openolt::Empty* response){

    // The actual RPC.
    Status status = stub_->EnablePonIf(context, request, response);

    // Act upon its status.
    if (status.ok()) {
      return Status::OK;
    } else {
      std::cout << status.error_code() << ": " << status.error_message()
                << std::endl;
      return Status(grpc::,status.error_message());  //Need to error the error_code
    }
  }
 Status DisablePonIf(
            ServerContext* context,
            const openolt::Interface* request,
            openolt::Empty* response) {

    // The actual RPC.
    Status status = stub_->DisablePonIf(context, request, response);

    // Act upon its status.
    if (status.ok()) {
      return Status::OK;
    } else {
      std::cout << status.error_code() << ": " << status.error_message()
                << std::endl;
      return Status(grpc::,status.error_message());  //Need to error the error_code
    }
  }
 Status CollectStatistics(
            ServerContext* context,
            const openolt::Empty* request,
            openolt::Empty* response) {

    // The actual RPC.
    Status status = stub_->CollectStatistics(context, request, response);

    // Act upon its status.
    if (status.ok()) {
      return Status::OK;
    } else {
      std::cout << status.error_code() << ": " << status.error_message()
                << std::endl;
      return Status(grpc::,status.error_message());  //Need to error the error_code
    }
  }
 Status Reboot(
            ServerContext* context,
            const openolt::Empty* request,
            openolt::Empty* response){

    // The actual RPC.
    Status status = stub_->Reboot(context, request, response);

    // Act upon its status.
    if (status.ok()) {
      return Status::OK;
    } else {
      std::cout << status.error_code() << ": " << status.error_message()
                << std::endl;
      return Status(grpc::,status.error_message());  //Need to error the error_code
    }
  }
 Status GetDeviceInfo(
            ServerContext* context,
            const openolt::Empty* request,
            openolt::DeviceInfo* response) {

    // The actual RPC.
    Status status = stub_->GetDeviceInfo(context, request, response);

    // Act upon its status.
    if (status.ok()) {
      return Status::OK;
    } else {
      std::cout << status.error_code() << ": " << status.error_message()
                << std::endl;
      return Status(grpc::,status.error_message());  //Need to error the error_code
    }
  }
 Status CreateTrafficSchedulers(
            ServerContext* context,
            const tech_profile::TrafficSchedulers* request,
            openolt::Empty* response) {

    // The actual RPC.
    Status status = stub_->CreateTrafficSchedulers(context, request, response);

    // Act upon its status.
    if (status.ok()) {
      return Status::OK;
    } else {
      std::cout << status.error_code() << ": " << status.error_message()
                << std::endl;
      return Status(grpc::,status.error_message());  //Need to error the error_code
    }
  }
 Status RemoveTrafficSchedulers(
            ServerContext* context,
            const tech_profile::TrafficSchedulers* request,
            openolt::Empty* response){

    // The actual RPC.
    Status status = stub_->RemoveTrafficSchedulers(context, request, response);

    // Act upon its status.
    if (status.ok()) {
      return Status::OK;
    } else {
      std::cout << status.error_code() << ": " << status.error_message()
                << std::endl;
      return Status(grpc::,status.error_message());  //Need to error the error_code
    }
  }
 Status CreateTrafficQueues(
            ServerContext* context,
            const tech_profile::TrafficQueues* request,
            openolt::Empty* response) {

    // The actual RPC.
    Status status = stub_->CreateTrafficQueues(context, request, response);

    // Act upon its status.
    if (status.ok()) {
      return Status::OK;
    } else {
      std::cout << status.error_code() << ": " << status.error_message()
                << std::endl;
      return Status(grpc::,status.error_message());  //Need to error the error_code
    }
  }
 Status RemoveTrafficQueues(
            ServerContext* context,
            const tech_profile::TrafficQueues* request,
            openolt::Empty* response){

    // The actual RPC.
    Status status = stub_->RemoveTrafficQueues(context, request, response);

    // Act upon its status.
    if (status.ok()) {
      return Status::OK;
    } else {
      std::cout << status.error_code() << ": " << status.error_message()
                << std::endl;
      return Status(grpc::,status.error_message());  //Need to error the error_code
    }
  }
 Status PerformGroupOperation(
            ServerContext* context,
            const openolt::Group* request,
            openolt::Empty* response){

    // The actual RPC.
    Status status = stub_->PerformGroupOperation(context, request, response);

    // Act upon its status.
    if (status.ok()) {
      return Status::OK;
    } else {
      std::cout << status.error_code() << ": " << status.error_message()
                << std::endl;
      return Status(grpc::,status.error_message());  //Need to error the error_code
    }
  }
 Status DeleteGroup(
            ServerContext* context,
            const openolt::Group* request,
            openolt::Empty* response){

    // The actual RPC.
    Status status = stub_->DeleteGroup(context, request, response);

    // Act upon its status.
    if (status.ok()) {
      return Status::OK;
    } else {
      std::cout << status.error_code() << ": " << status.error_message()
                << std::endl;
      return Status(grpc::,status.error_message());  //Need to error the error_code
    }
  }
 Status OnuItuPonAlarmSet(
            ServerContext* context,
            const openolt::OnuItuPonAlarm* request,
            openolt::Empty* response) {

    // The actual RPC.
    Status status = stub_->OnuItuPonAlarmSet(context, request, response);

    // Act upon its status.
    if (status.ok()) {
      return Status::OK;
    } else {
      std::cout << status.error_code() << ": " << status.error_message()
                << std::endl;
      return Status(grpc::,status.error_message());  //Need to error the error_code
    }
  }
 Status GetLogicalOnuDistanceZero(
            ServerContext* context,
            const openolt::Onu* request,
            openolt::OnuLogicalDistance* response){

    // The actual RPC.
    Status status = stub_->GetLogicalOnuDistanceZero(context, request, response);

    // Act upon its status.
    if (status.ok()) {
      return Status::OK;
    } else {
      std::cout << status.error_code() << ": " << status.error_message()
                << std::endl;
      return Status(grpc::,status.error_message());  //Need to error the error_code
    }
  }
 Status GetLogicalOnuDistance(
            ServerContext* context,
            const openolt::Onu* request,
            openolt::OnuLogicalDistance* response){

    // The actual RPC.
    Status status = stub_->GetLogicalOnuDistance(context, request, response);

    // Act upon its status.
    if (status.ok()) {
      return Status::OK;
    } else {
      std::cout << status.error_code() << ": " << status.error_message()
                << std::endl;
      return Status(grpc::,status.error_message());  //Need to error the error_code
    }
  }

 private:
  std::unique_ptr<Stub> stub_;
  
 public:
 ProxyClient* connectToServer()
 {
	 std::string target_str; // agent IP address
  	 std::string arg_str("--target");
  	if (argc > 1) {
    		std::string arg_val = argv[1];
    		size_t start_pos = arg_val.find(arg_str);
    		if (start_pos != std::string::npos) {
      			start_pos += arg_str.size();
      			if (arg_val[start_pos] == '=') {
        			target_str = arg_val.substr(start_pos + 1);
      			} else {
        		std::cout << "The only correct argument syntax is --target=" << std::endl;
        		return 0;
      			}
    		} else {
      		std::cout << "The only acceptable argument is --target=" << std::endl;
      		return 0;
   		 }
  	} else {
    	target_str = "0.0.0.0:9191";
  	}

  return new ProxyClient(grpc::CreateChannel(
      target_str, grpc::InsecureChannelCredentials()));
  
 }
};
