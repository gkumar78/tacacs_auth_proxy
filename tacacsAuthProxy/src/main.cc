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

using namespace std;

int main(int argc, char** argv) {

    for (int i = 1; i < argc; ++i) {
        if(strcmp(argv[i-1], "--interface") == 0 || (strcmp(argv[i-1], "--intf") == 0)) {
            grpc_server_interface_name = argv[i];
            break;
        }
        if(strcmp(argv[i-1], "--server") == 0 ) {
            tacacs_server_address = argv[i];
            break;
        }
    }

    ProxyServer proxy;
    TaccController tacc(tacacs_server_address,tacacs_secure_key,tacacs_fallback_pass);  

    proxy.RunServer(argc, argv);

    return 0;
}

