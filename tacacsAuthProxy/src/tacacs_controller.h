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

extern "C" {
#include "libtac/include/libtac.h"
#include "libtac/include/tacplus.h"
}

using namespace std;

class TaccController {
    int tac_fd;
    int ret;
    struct areply arep;
    time_t t;
    struct tm tm;
    char buf[40];
    int task_id;
    char* service;
    char* protocol;

    const char* server_address;
    const char* secure_key;
    bool fallback_pass;

    struct addrinfo *tac_server;
    int retVal;


  public:
    TaccController(const char* server_address, const char* secure_key, bool fallback_pass);

    int Authenticate(const char* user, const char* pass);
    int Authorize(const char* user, const char* pass, std::string methodName);
    int StartAccounting(std::string methodName);
    int StopAccounting(std::string methodName);
};
