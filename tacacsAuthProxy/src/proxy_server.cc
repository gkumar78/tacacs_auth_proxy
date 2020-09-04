/*
 * Copyright 2018-present Open Networking Foundation
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <iostream>
#include <memory>
#include <string>
#include <sstream>
#include <grpcpp/grpcpp.h>
#include <grpcpp/health_check_service_interface.h>
#include <grpcpp/ext/proto_server_reflection_plugin.h>


using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::Status;
using namespace std;

static const std::string base64_chars =
             "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
             "abcdefghijklmnopqrstuvwxyz"
             "0123456789+/";

static inline bool is_base64(unsigned char c) {
        return (isalnum(c) || (c == '+') || (c == '/'));
}
std::string base64_decode(std::string const& encoded_string);

class ProxyServiceImpl final : public ProxyServer::Service,  { // add client interface and change class name

    static class accoutingWrapper {
        String methodName;
        Status (*clientFunc)();

        public: 
	accoutingWrapper(String method, Status (*clientFunc)())  	 	
                : methodName(method),
                  clientFunc(clientFunc);

        Status  invoke() {
                AccoutingStart(methodName);
                Status status = this.clientFunc;
                AccoutingStop(methodName);
                return status;
        }

    }

    Status processTacacsAuth(ServerContext* context, String methodName) {
        // Is TACACS enabled, if not proceed to client invocation
        // Extract Auth Credentials
        // Call TACACS_Server class to authenticate
        // If not authenticated,
        const std::multimap<grpc::string_ref, grpc::string_ref> metadata = context->client_metadata();
        std::multimap<grpc::string_ref, grpc::string_ref>::const_iterator data_iter = metadata.find("authorization");

        if(data_iter != metadata.end()) {
                string str_withBasic((data_iter->second).data(),(data_iter->second).length());
                std::string str_withoutBasic = str_withBasic.substr(6);
                std::string decoded_str = base64_decode(str_withoutBasic);
                int pos = decoded_str.find(":");
                std::string username = decoded_str.substr(0,pos);
                std::string password = decoded_str.substr(pos+1);
                cout << "\nUsername: "<< username << "\nPassword: "<< password<<endl;
                Status authenStatus = Authenticate(username, password);
                if (authenStatus != Status::OK) {
                        return Status(grpc::UNAUTHENTICATED,"Authentication against TACACS Server failed");
                }
                Status authorStatus = Authorize(username, password);
                if (authorStatus != Status::OK) {
                        return Status(grpc::PERMISSION_DENIED,"Authorization of User for Invoked Operation against TACACS Server failed");
                }

                return Status::OK;
        }
        else {
	    	return Status(grpc::INVALID_ARGUMENT,"Unable to find or extract credentials from incoming gRPC request");
        }

    }

    Status DisableOlt(
            ServerContext* context,
            const openolt::Empty* request,
            openolt::Empty* response) override {
                ProxyClient* client; //added by Tirthankar
		Status authResult = processTacacsAuth(context, "DisableOlt");
                if( authResult != Status:OK ) {
                        return authResult;
                }

                auto disableOLT = []() -> Status { 
	
		return client->connectToServer()->DisableOlt(context, request, response); }
                return accoutingWrapper("DisableOlt", disableOLT).invoke();

    }

    Status ReenableOlt(
            ServerContext* context,
            const openolt::Empty* request,
            openolt::Empty* response) override {
              ProxyClient* client;
              Status authResult = processTacacsAuth(context, "ReenableOlt");
                if( authResult != Status:OK ) {
                        return authResult;
                }
                auto reenableOLT = []() -> Status { return client->connectToServer()->ReenableOlt(context, request, response); }
                return accoutingWrapper("ReenableOlt", reenableOLT).invoke();
    }

    Status ActivateOnu(
            ServerContext* context,
            const openolt::Onu* request,
            openolt::Empty* response) override {
              	   ProxyClient* client;
		   Status authResult = processTacacsAuth(context, "ActivateOnu");
                if( authResult != Status:OK ) {
                        return authResult;
                }

                auto activateONU = []() -> Status { return client->connectToServer()->ActivateOnu(context, request, response); }
                return accoutingWrapper("ActivateOnu", activateONU).invoke();
    }

    Status DeactivateOnu(
            ServerContext* context,
            const openolt::Onu* request,
            openolt::Empty* response) override {
                 ProxyClient* client;
		Status authResult = processTacacsAuth(context, "DeactivateOnu");
                if( authResult != Status:OK ) {
                        return authResult;
                }

                auto deactivateOnu = []() -> Status { return client->connectToServer()->DeactivateOnu(context, request, response); }
                return accoutingWrapper("DeactivateOnu", deactivateOnu).invoke();
    }

    Status DeleteOnu(
            ServerContext* context,
            const openolt::Onu* request,
            openolt::Empty* response) override {
                ProxyClient* client;
		 Status authResult = processTacacsAuth(context, "DeleteOnu");
                if( authResult != Status:OK ) {
                        return authResult;
                }

                auto deleteOnu = []() -> Status { return client->connectToServer()->DeleteOnu(context, request, response); }
                return accoutingWrapper("DeleteOnu", deleteOnu).invoke();
    }

    Status OmciMsgOut(
            ServerContext* context,
            const openolt::OmciMsg* request,
            openolt::Empty* response) override {
                ProxyClient* client; 
		Status authResult = processTacacsAuth(context, "OmciMsgOut");
                if( authResult != Status:OK ) {
                        return authResult;
                }

                auto omciMsgOut = []() -> Status { return client->connectToServer()->OmciMsgOut(context, request, response); }
                return accoutingWrapper("OmciMsgOut", omciMsgOut).invoke();
    }

    Status OnuPacketOut(
            ServerContext* context,
            const openolt::OnuPacket* request,
            openolt::Empty* response) override {
                ProxyClient* client; 
		Status authResult = processTacacsAuth(context, "OnuPacketOut");
                if( authResult != Status:OK ) {
                        return authResult;
                }

                auto onuPacketOut = []() -> Status { return client->connectToServer()->OnuPacketOut(context, request, response); }
                return accoutingWrapper("OnuPacketOut", onuPacketOut).invoke();
    }

    Status UplinkPacketOut(
            ServerContext* context,
            const openolt::UplinkPacket* request,
            openolt::Empty* response) override {
                ProxyClient* client; 
		Status authResult = processTacacsAuth(context, "UplinkPacketOut");
                if( authResult != Status:OK ) {
                        return authResult;
                }

                auto uplinkPacketOut = []() -> Status { return client->connectToServer()->UplinkPacketOut(context, request, response); }
                return accoutingWrapper("UplinkPacketOut", uplinkPacketOut).invoke();
    }

   Status FlowAdd(
            ServerContext* context,
            const openolt::Flow* request,
            openolt::Empty* response) override {
                 ProxyClient* client;
                 Status authResult = processTacacsAuth(context, "FlowAdd");
                if( authResult != Status:OK ) {
                        return authResult;
                }

                auto flowAdd = []() -> Status { return client->connectToServer()->FlowAdd(context, request, response); }
                return accoutingWrapper("FlowAdd", flowAdd).invoke();
    }

    Status FlowRemove(
            ServerContext* context,
            const openolt::Flow* request,
            openolt::Empty* response) override {
                ProxyClient* client; 
		Status authResult = processTacacsAuth(context, "FlowRemove");
                if( authResult != Status:OK ) {
                        return authResult;
                }

                auto flowRemove = []() -> Status { return client->connectToServer()->FlowRemove(context, request, response); }
                return accoutingWrapper("FlowRemove", flowRemove).invoke();
    }

    Status EnableIndication(
            ServerContext* context,
            const ::openolt::Empty* request,
            ServerWriter<openolt::Indication>* writer) override {
     		ProxyClient* client;
                Status authResult = processTacacsAuth(context, "EnableIndication");
                if( authResult != Status:OK ) {
                        return authResult;
                }

                auto enableIndication = []() -> Status { return client->connectToServer()->EnableIndication(context, request, response); }
                return accoutingWrapper("EnableIndication", enableIndication).invoke();   
    }

    Status HeartbeatCheck(
            ServerContext* context,
            const openolt::Empty* request,
            openolt::Heartbeat* response) override {
                ProxyClient* client;
		Status authResult = processTacacsAuth(context, "HeartbeatCheck");
                if( authResult != Status:OK ) {
                        return authResult;
                }

                auto heartbeatCheck = []() -> Status { return client->connectToServer()->HeartbeatCheck(context, request, response); }
                return accoutingWrapper("HeartbeatCheck", heartbeatCheck).invoke();
    }

    Status EnablePonIf(
            ServerContext* context,
            const openolt::Interface* request,
            openolt::Empty* response) override {
		ProxyClient* client;
                 Status authResult = processTacacsAuth(context, "EnablePonIf");
                if( authResult != Status:OK ) {
                       return authResult;
                }

                auto EnablePonIf = []() -> Status { return client->connectToServer()->EnablePonIf(context, request, response); }
                return accoutingWrapper("EnablePonIf", enablePonIf).invoke();
    }

    /*Status GetPonIf(
            ServerContext* context,
            const openolt::Interface* request,
            openolt::IntfIndication* response) override {
        // TODO - Return the oper status of the pon interface
        return Status::OK;
    }*/

    Status DisablePonIf(
            ServerContext* context,
            const openolt::Interface* request,
            openolt::Empty* response) override {
		ProxyClient* client;
                 Status authResult = processTacacsAuth(context, "DisablePonIf");
                if( authResult != Status:OK ) {
                        return authResult;
                }

                auto disablePonIf = []() -> Status { return client->connectToServer()->DisablePonIf(context, request, response); }
                return accoutingWrapper("DisablePonIf", disablePonIf).invoke();
    }

    Status CollectStatistics(
            ServerContext* context,
            const openolt::Empty* request,
            openolt::Empty* response) override {
		ProxyClient* client;
                 Status authResult = processTacacsAuth(context, "CollectStatistics");
                if( authResult != Status:OK ) {
                        return authResult;
                }
                auto collectStatistics = []() -> Status { return client->connectToServer()->CollectStatistics(context, request, response); }
                return accoutingWrapper("CollectStatistics", collectStatistics).invoke();
    }

    Status Reboot(
            ServerContext* context,
            const openolt::Empty* request,
            openolt::Empty* response) override {
		ProxyClient* client;
                 Status authResult = processTacacsAuth(context, "Reboot");
                if( authResult != Status:OK ) {
                        return authResult;
                }

                auto reboot = []() -> Status { return client->connectToServer()->Reboot(context, request, response); }
                return accoutingWrapper("Reboot", reboot).invoke();
    }

    Status GetDeviceInfo(
            ServerContext* context,
            const openolt::Empty* request,
            openolt::DeviceInfo* response) override {
		 ProxyClient* client;
                 Status authResult = processTacacsAuth(context, "GetDeviceInfo");
                if( authResult != Status:OK ) {
                        return authResult;
                }

                auto disableOLT = []() -> Status { return client->connectToServer()->GetDeviceInfo(context, request, response); }
                return accoutingWrapper("GetDeviceInfo", getDeviceInfo).invoke();
    }

    Status CreateTrafficSchedulers(
            ServerContext* context,
            const tech_profile::TrafficSchedulers* request,
            openolt::Empty* response) override {
		 ProxyClient* client;
                 Status authResult = processTacacsAuth(context, "CreateTrafficSchedulers");
                if(authResult != Status:OK ) {
                        return authResult;
                }

                auto createTrafficSchedulers = []() -> Status { return client->connectToServer()->CreateTrafficSchedulers(context, request, response); }
                return accoutingWrapper("CreateTrafficSchedulers", createTrafficSchedulers).invoke();
    };

    Status RemoveTrafficSchedulers(
            ServerContext* context,
            const tech_profile::TrafficSchedulers* request,
            openolt::Empty* response) override {
		ProxyClient* client;
                 Status authResult = processTacacsAuth(context, "RemoveTrafficSchedulers");
                if( authResult != Status:OK ) {
                        return authResult;
                }

                auto remTrafficSchedulers = []() -> Status { return client->connectToServer()->RemoveTrafficSchedulers(context, request, response); }
                return accoutingWrapper("RemoveTrafficSchedulers", remTrafficSchedulers).invoke();
    };

    Status CreateTrafficQueues(
            ServerContext* context,
            const tech_profile::TrafficQueues* request,
            openolt::Empty* response) override {
		ProxyClient* client;
                 Status authResult = processTacacsAuth(context, "CreateTrafficQueues");
                if( authResult != Status:OK ) {
                        return authResult;
                }

                auto createTrafficQueues = []() -> Status { return client->connectToServer()->CreateTrafficQueues(context, request, response); }
                return accoutingWrapper("CreateTrafficQueues", createTrafficQueues).invoke();
    };

    Status RemoveTrafficQueues(
            ServerContext* context,
            const tech_profile::TrafficQueues* request,
            openolt::Empty* response) override {
		ProxyClient*client;	
                 Status authResult = processTacacsAuth(context, "RemoveTrafficQueues");
                if( authResult != Status:OK ) {
                        return authResult;
                }

                auto removeTrafficQueues = []() -> Status { return client->connectToServer()->RemoveTrafficQueues(context, request, response); }
                return accoutingWrapper("RemoveTrafficQueues", removeTrafficQueues).invoke();
    };

    Status PerformGroupOperation(
            ServerContext* context,
            const openolt::Group* request,
            openolt::Empty* response) override {
		ProxyClient* client;
                 Status authResult = processTacacsAuth(context, "PerformGroupOperation");
                if( authResult != Status:OK ) {
                        return authResult;
                }

                auto performGroupOperation = []() -> Status { return client->connectToServer()->PerformGroupOperation(context, request, response); }
                return accoutingWrapper("PerformGroupOperation", performGroupOperation).invoke();
    };

    Status DeleteGroup(
            ServerContext* context,
            const openolt::Group* request,
            openolt::Empty* response) override {
		ProxyClient* client;
                 Status authResult = processTacacsAuth(context, "DeleteGroup");
                if( authResult != Status:OK ) {
                        return authResult;
                }

                auto deleteGroup = []() -> Status { return client->connectToServer()->DeleteGroup(context, request, response); }
                return accoutingWrapper("DeleteGroup", deleteGroup).invoke();
    };

    Status OnuItuPonAlarmSet(
            ServerContext* context,
            const openolt::OnuItuPonAlarm* request,
            openolt::Empty* response) override {
		ProxyClient* client;
                 Status authResult = processTacacsAuth(context, "onuItuPonAlarmSet");
                if( authResult != Status:OK ) {
                        return authResult;
                }

                auto onuItuPonAlarmSet = []() -> Status { return client->connectToServer()->OnuItuPonAlarmSet(context, request, response); }
                return accoutingWrapper("OnuItuPonAlarmSet", onuItuPonAlarmSet).invoke();
    };

    Status GetLogicalOnuDistanceZero(
            ServerContext* context,
           const openolt::Onu* request,
            openolt::OnuLogicalDistance* response) override {
		ProxyClient* client;
                 Status authResult = processTacacsAuth(context, "GetLogicalOnuDistanceZero");
                if( authResult != Status:OK ) {
                        return authResult;
                }

                auto getLogicalOnuDistanceZero = []() -> Status { return client->connectToServer()->GetLogicalOnuDistanceZero(context, request, response); }
                return accoutingWrapper("GetLogicalOnuDistanceZero", getLogicalOnuDistanceZero).invoke();
    };

    Status GetLogicalOnuDistance(
            ServerContext* context,
            const openolt::Onu* request,
            openolt::OnuLogicalDistance* response) override {
		ProxyClient* client;
                 Status authResult = processTacacsAuth(context, "GetLogicalOnuDistance");
                if( authResult != Status:OK ) {
                        return authResult;
                }

                auto getLogicalOnuDistance = []() -> Status { return client->connectToServer()->GetLogicalOnuDistance(context, request, response); }
                return accoutingWrapper("GetLogicalOnuDistance", getLogicalOnuDistance).invoke();
    };

};

std::string base64_decode(std::string const& encoded_string) {
  int in_len = encoded_string.size();
  int i = 0;
  int j = 0;
  int in_ = 0;
  unsigned char char_array_4[4], char_array_3[3];
  std::string ret;

  while (in_len-- && ( encoded_string[in_] != '=') && is_base64(encoded_string[in_])) {
    char_array_4[i++] = encoded_string[in_]; in_++;
    if (i ==4) {
      for (i = 0; i <4; i++)
        char_array_4[i] = base64_chars.find(char_array_4[i]);

      char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
      char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
      char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

      for (i = 0; (i < 3); i++)
        ret += char_array_3[i];
      i = 0;
    }
  }

  if (i) {
    for (j = i; j <4; j++)
      char_array_4[j] = 0;

    for (j = 0; j <4; j++)
      char_array_4[j] = base64_chars.find(char_array_4[j]);

    char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
    char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
    char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

    for (j = 0; (j < i - 1); j++) ret += char_array_3[j];
  }

  return ret;
}

void RunServer(int argc, char** argv) {
  //change this address and make the required changes for sub interface
  std::string server_address("0.0.0.0:9191");
  GreeterServiceImpl service;

  grpc::EnableDefaultHealthCheckService(true);
  grpc::reflection::InitProtoReflectionServerBuilderPlugin();
  ServerBuilder builder;

  builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());

  builder.RegisterService(&service);

  std::unique_ptr<Server> server(builder.BuildAndStart());
  std::cout << "Server listening on " << server_address << std::endl;

  server->Wait();
}
