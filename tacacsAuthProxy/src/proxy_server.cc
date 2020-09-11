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
#include <grpcpp/health_check_service_interface.h>
#include <grpcpp/ext/proto_server_reflection_plugin.h>
#include <grpcpp/grpcpp.h>

#include <voltha_protos/openolt.grpc.pb.h>
#include <voltha_protos/tech_profile.grpc.pb.h>

#include "tacacs_controller.h"
#include "logger.h"

using grpc::Channel;
using grpc::ChannelArguments;
using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::Status;
using grpc::ClientContext;

using namespace std;

static const std::string base64_chars =
"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
"abcdefghijklmnopqrstuvwxyz"
"0123456789+/";

static inline bool is_base64(unsigned char c) {
    return (isalnum(c) || (c == '+') || (c == '/'));
}

static Server* ServerInstance;

std::string base64_decode(std::string const& encoded_string);

class ProxyServiceImpl final : public openolt::Openolt::Service  {

    TaccController *taccController;
    unique_ptr<openolt::Openolt::Stub> openoltClientStub;

    public:
    TacacsContext extractDataFromGrpc(ServerContext* context) {
        LOG_F(INFO, "Extracting the gRPC credentials");
        const std::multimap<grpc::string_ref, grpc::string_ref> metadata = context->client_metadata();
        std::multimap<grpc::string_ref, grpc::string_ref>::const_iterator data_iter = metadata.find("authorization");

        TacacsContext tacCtx;

        if(data_iter != metadata.end()) {
            string str_withBasic((data_iter->second).data(),(data_iter->second).length());
            std::string str_withoutBasic = str_withBasic.substr(6);
            std::string decoded_str = base64_decode(str_withoutBasic);
            int pos = decoded_str.find(":");
            tacCtx.username = decoded_str.substr(0,pos);
            tacCtx.password = decoded_str.substr(pos+1);
            tacCtx.remote_addr = context->peer();
            LOG_F(INFO, "Received gRPC credentials username=%s, password=%s from Remote %s", tacCtx.username.c_str(), tacCtx.password.c_str(), tacCtx.remote_addr.c_str());
        } else {
            tacCtx.username = "";
        }

        return tacCtx;
    }

    Status processTacacsAuth(TacacsContext* tacCtx){
        LOG_F(INFO, "Calling Authenticate");
        Status status = taccController->Authenticate(tacCtx);
        if(status.error_code() == StatusCode::OK) {
            LOG_F(INFO, "Calling Authorize");
            status = taccController->Authorize(tacCtx);
        }
        return status;
    }

    Status DisableOlt(
            ServerContext* context,
            const openolt::Empty* request,
            openolt::Empty* response) override {
        LOG_F(INFO, "DisableOlt invoked");

        if (taccController->IsTacacsEnabled()) {
            TacacsContext tacCtx = extractDataFromGrpc(context);
            if (tacCtx.username.empty()) {
                return Status(grpc::INVALID_ARGUMENT,"Unable to find or extract credentials from incoming gRPC request");
            }

            tacCtx.method_name = "disableolt";
            string error_msg = "no error";
            LOG_F(INFO, "processTacacsAuth: username=%s, password=%s", tacCtx.username.c_str(), tacCtx.password.c_str());
            taccController->StartAccounting(&tacCtx);

            Status status = processTacacsAuth(&tacCtx);
            if(status.error_code() == StatusCode::OK) {
                ClientContext ctx;
                LOG_F(INFO, "Calling disableOLT");
                status = openoltClientStub->DisableOlt(&ctx, *request, response);
            }
            if(status.error_code() != StatusCode::OK) {
                error_msg = status.error_message();
            }
            taccController->StopAccounting(&tacCtx, error_msg);
            return status;
        } else {
            ClientContext ctx;
            LOG_F(INFO, "Tacacs disabled.. Calling disableOLT");
            return openoltClientStub->DisableOlt(&ctx, *request, response);
        }
    }


    Status ReenableOlt(
            ServerContext* context,
            const openolt::Empty* request,
            openolt::Empty* response) override {
        LOG_F(INFO, "ReenableOlt invoked");

        if (taccController->IsTacacsEnabled()) {
            TacacsContext tacCtx = extractDataFromGrpc(context);
            if (tacCtx.username.empty()) {
                return Status(grpc::INVALID_ARGUMENT,"Unable to find or extract credentials from incoming gRPC request");
            }

            tacCtx.method_name = "reenableolt";
            string error_msg = "no error";
            LOG_F(INFO, "processTacacsAuth: username=%s, password=%s", tacCtx.username.c_str(), tacCtx.password.c_str());
            taccController->StartAccounting(&tacCtx);

            Status status = processTacacsAuth(&tacCtx);
            if(status.error_code() == StatusCode::OK) {
                ClientContext ctx;
                LOG_F(INFO, "Calling ReenableOlt");
                status = openoltClientStub->ReenableOlt(&ctx, *request, response);
            }
            if(status.error_code() != StatusCode::OK) {
                error_msg = status.error_message();
            }
            taccController->StopAccounting(&tacCtx, error_msg);
            return status;
        } else {
            ClientContext ctx;
            LOG_F(INFO, "Tacacs disabled.. Calling ReenableOlt");
            return openoltClientStub->ReenableOlt(&ctx, *request, response);
        }
    }


    Status HeartbeatCheck(
            ServerContext* context,
            const openolt::Empty* request,
            openolt::Heartbeat* response) override {
        LOG_F(INFO, "HeartbeatCheck invoked");

        if (taccController->IsTacacsEnabled()) {
            TacacsContext tacCtx = extractDataFromGrpc(context);
            if (tacCtx.username.empty()) {
                return Status(grpc::INVALID_ARGUMENT,"Unable to find or extract credentials from incoming gRPC request");
            }

            tacCtx.method_name = "heartbeatcheck";
            string error_msg = "no error";
            LOG_F(INFO, "processTacacsAuth: username=%s, password=%s", tacCtx.username.c_str(), tacCtx.password.c_str());
            taccController->StartAccounting(&tacCtx);

            Status status = processTacacsAuth(&tacCtx);
            if(status.error_code() == StatusCode::OK) {
                ClientContext ctx;
                LOG_F(INFO, "Calling HeartbeatCheck");
                status = openoltClientStub->HeartbeatCheck(&ctx, *request, response);
            }
            if(status.error_code() != StatusCode::OK) {
                error_msg = status.error_message();
            }
            taccController->StopAccounting(&tacCtx, error_msg);
            return status;
        } else {
            ClientContext ctx;
            LOG_F(INFO, "Tacacs disabled.. Calling HeartbeatCheck");
            return openoltClientStub->HeartbeatCheck(&ctx, *request, response);
        }
    }

    Status CreateTrafficSchedulers(
            ServerContext* context,
            const tech_profile::TrafficSchedulers* request,
            openolt::Empty* response) override {
        LOG_F(INFO, "CreateTrafficSchedulers invoked");

        if (taccController->IsTacacsEnabled()) {
            TacacsContext tacCtx = extractDataFromGrpc(context);
            if (tacCtx.username.empty()) {
                return Status(grpc::INVALID_ARGUMENT,"Unable to find or extract credentials from incoming gRPC request");
            }

            tacCtx.method_name = "createtrafficschedulers";
            string error_msg = "no error";
            LOG_F(INFO, "processTacacsAuth: username=%s, password=%s", tacCtx.username.c_str(), tacCtx.password.c_str());
            taccController->StartAccounting(&tacCtx);

            Status status = processTacacsAuth(&tacCtx);
            if(status.error_code() == StatusCode::OK) {
                ClientContext ctx;
                LOG_F(INFO, "Calling CreateTrafficSchedulers");
                status = openoltClientStub->CreateTrafficSchedulers(&ctx, *request, response);
            }
            if(status.error_code() != StatusCode::OK) {
                error_msg = status.error_message();
            }
            taccController->StopAccounting(&tacCtx, error_msg);
            return status;
        } else {
            ClientContext ctx;
            LOG_F(INFO, "Tacacs disabled.. Calling CreateTrafficSchedulers");
            return openoltClientStub->CreateTrafficSchedulers(&ctx, *request, response);
        }
    }

    Status RemoveTrafficSchedulers(
            ServerContext* context,
            const tech_profile::TrafficSchedulers* request,
            openolt::Empty* response) override {
        LOG_F(INFO, "RemoveTrafficSchedulers invoked");

        if (taccController->IsTacacsEnabled()) {
            TacacsContext tacCtx = extractDataFromGrpc(context);
            if (tacCtx.username.empty()) {
                return Status(grpc::INVALID_ARGUMENT,"Unable to find or extract credentials from incoming gRPC request");
            }

            tacCtx.method_name = "removetrafficschedulers";
            string error_msg = "no error";
            LOG_F(INFO, "processTacacsAuth: username=%s, password=%s", tacCtx.username.c_str(), tacCtx.password.c_str());
            taccController->StartAccounting(&tacCtx);

            Status status = processTacacsAuth(&tacCtx);
            if(status.error_code() == StatusCode::OK) {
                ClientContext ctx;
                LOG_F(INFO, "Calling RemoveTrafficSchedulers");
                status = openoltClientStub->RemoveTrafficSchedulers(&ctx, *request, response);
            }
            if(status.error_code() != StatusCode::OK) {
                error_msg = status.error_message();
            }
            taccController->StopAccounting(&tacCtx, error_msg);
            return status;
        } else {
            ClientContext ctx;
            LOG_F(INFO, "Tacacs disabled.. Calling RemoveTrafficSchedulers");
            return openoltClientStub->RemoveTrafficSchedulers(&ctx, *request, response);
        }
    }

    Status CreateTrafficQueues(
            ServerContext* context,
            const tech_profile::TrafficQueues* request,
            openolt::Empty* response) override {
        LOG_F(INFO, "CreateTrafficQueues invoked");

        if (taccController->IsTacacsEnabled()) {
            TacacsContext tacCtx = extractDataFromGrpc(context);
            if (tacCtx.username.empty()) {
                return Status(grpc::INVALID_ARGUMENT,"Unable to find or extract credentials from incoming gRPC request");
            }

            tacCtx.method_name = "CreateTrafficQueues";
            string error_msg = "no error";
            LOG_F(INFO, "processTacacsAuth: username=%s, password=%s", tacCtx.username.c_str(), tacCtx.password.c_str());
            taccController->StartAccounting(&tacCtx);

            Status status = processTacacsAuth(&tacCtx);
            if(status.error_code() == StatusCode::OK) {
                ClientContext ctx;
                LOG_F(INFO, "Calling CreateTrafficQueues");
                status = openoltClientStub->CreateTrafficQueues(&ctx, *request, response);
            }
            if(status.error_code() != StatusCode::OK) {
                error_msg = status.error_message();
            }
            taccController->StopAccounting(&tacCtx, error_msg);
            return status;
        } else {
            ClientContext ctx;
            LOG_F(INFO, "Tacacs disabled.. Calling CreateTrafficQueues");
            return openoltClientStub->CreateTrafficQueues(&ctx, *request, response);
        }
    }

    ProxyServiceImpl(TaccController* tacctrl, const char* addr) {
        taccController = tacctrl;

        LOG_F(INFO, "Creating GRPC Channel to Openolt Agent on %s", addr);
        openoltClientStub = openolt::Openolt::NewStub(grpc::CreateChannel(addr, grpc::InsecureChannelCredentials()));
    }

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
    const char* tacacs_server_address = NULL;
    const char* tacacs_secure_key = NULL;
    bool tacacs_fallback_pass = true;
    const char* interface_address = NULL;
    const char* openolt_agent_address = NULL;
    TaccController* taccController = NULL;

    LOG_F(INFO, "Starting up TACACS Proxy");

    for (int i = 1; i < argc; ++i) {
        if(strcmp(argv[i-1], "--tacacs_server_address") == 0 ) {
            tacacs_server_address = argv[i];
        } else if(strcmp(argv[i-1], "--tacacs_secure_key") == 0 ) {
            tacacs_secure_key = argv[i];
        } else if(strcmp(argv[i-1], "--tacacs_fallback_pass") == 0 ) {
            tacacs_fallback_pass = ( *argv[i] == '0') ? false : true;
        } else if(strcmp(argv[i-1], "--interface_address") == 0 ) {
            interface_address = argv[i];
        } else if(strcmp(argv[i-1], "--openolt_agent_address") == 0 ) {
            openolt_agent_address = argv[i];
        }
    }

    if(!interface_address || interface_address == ""){
        LOG_F(ERROR, "Server Interface Bind address is missing. TACACS Proxy startup failed");
        return; 
    }

    if(!openolt_agent_address || openolt_agent_address == ""){
        LOG_F(ERROR, "Openolt Agent address is missing. TACACS Proxy startup failed");
        return;
    }

    if(!tacacs_server_address || tacacs_server_address == ""){
        LOG_F(INFO, "TACACS+ Server address is missing. TACACS+ AAA will be disabled");
    }

    LOG_F(INFO, "TACACS+ Server configured as %s", tacacs_server_address);

    LOG_F(INFO, "TACACS Fallback configured as %s", tacacs_fallback_pass ? "PASS": "FAIL");

    if(!tacacs_secure_key){
        LOG_F(ERROR, "TACACS Secure Key is missing. No encryption will be used for TACACS channel");
        tacacs_secure_key = "";
    }

    LOG_F(INFO, "Creating TaccController");
    taccController = new TaccController(tacacs_server_address, tacacs_secure_key, tacacs_fallback_pass);

    LOG_F(INFO, "Creating Proxy Server");
    ProxyServiceImpl service(taccController, openolt_agent_address);

    grpc::EnableDefaultHealthCheckService(true);
    ServerBuilder builder;

    LOG_F(INFO, "Starting Proxy Server");
    builder.AddListeningPort(interface_address, grpc::InsecureServerCredentials());
    builder.RegisterService(&service);

    std::unique_ptr<Server> server(builder.BuildAndStart());

    ServerInstance = server.get();

    LOG_F(INFO, "TACACS Proxy listening on %s", interface_address);
    server->Wait();
}

void StopServer(int signum) {
    LOG_F(INFO, "Received Signal %d", signum);

    if( ServerInstance != NULL ) {
        LOG_F(INFO, "Shutting down TACACS Proxy");
        ServerInstance->Shutdown();
    }

    exit(0);
}
