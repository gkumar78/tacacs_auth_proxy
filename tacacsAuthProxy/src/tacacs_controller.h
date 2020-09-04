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
#include "grpcpp/grpcpp.h"

extern "C" {
#include "libtac/libtac.h"
#include "libtac/tacplus.h"
}


using namespace std;
using namespace grpc;

class TaccController {
    int tac_fd;

    const char* server_address;
    const char* secure_key;
    bool fallback_pass;

    char* remote_addr;
    char* tty;

  public:
    TaccController(const char* server_address, const char* secure_key, bool fallback_pass);

    Status Authenticate(const char* user, const char* pass);
    Status Authorize(const char* user, string methodName);
    int StartAccounting(const char* user, string methodName);
    void StopAccounting(const char* user, int task_id, string methodName);
};
