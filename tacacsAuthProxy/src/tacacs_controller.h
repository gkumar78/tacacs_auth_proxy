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
#include <stdio.h>
#include <syslog.h>
#include <cstring>
#include <ctime>
#include "grpcpp/grpcpp.h"

extern "C" {
#include "libtac/libtac.h"
#include "libtac/tacplus.h"
}


using namespace std;
using namespace grpc;

class TacacsContext {
    public:
        std::string username;
        std::string password;
        std::string remote_addr;
        std::string method_name;
        int task_id;
        time_t start_time;

        char* getUsername() {
            return const_cast<char*>(username.c_str());
        }

        char* getPassword() {
            return const_cast<char*>(password.c_str());
        }

        char* getRemoteAddr() {
            return const_cast<char*>(remote_addr.c_str());
        }

        char* getMethodName() {
            return const_cast<char*>(method_name.c_str());
        }

};

class TaccController {
    int tac_fd;

    const char* server_address;
    const char* secure_key;
    bool fallback_pass;

    public:
    TaccController(const char* server_address, const char* secure_key, bool fallback_pass);

    bool IsTacacsEnabled();
    Status Authenticate(TacacsContext* tacCtx);
    Status Authorize(TacacsContext* tacCtx);
    void StartAccounting(TacacsContext* tacCtx);
    void StopAccounting(TacacsContext* tacCtx, string err_msg);
};
