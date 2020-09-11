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

#include "tacacs_controller.h"
#include "logger.h"

char TAC_FIELD_TTY[] = "grpc_api";
char TAC_ATTR_SERVICE[] = "service";
char TAC_ATTR_CMD[] = "cmd";
char TAC_ATTR_START_TIME[] = "start_time";
char TAC_ATTR_STOP_TIME[] = "stop_time";
char TAC_ATTR_ELAPSED_TIME[] = "elapsed_time";
char TAC_ATTR_TASK_ID[] = "task_id";
char TAC_ATTR_ERR_MSG[] = "err_msg";
char TAC_ATTR_VALUE_SHELL[] = "shell";

TaccController::TaccController(const char* tacacs_server_address, const char* tacacs_secure_key, bool tacacs_fallback_pass){
        server_address = tacacs_server_address;
	secure_key = tacacs_secure_key;
	fallback_pass = tacacs_fallback_pass;
	remote_addr =  "1.1.1.1";
}

bool TaccController::IsTacacsEnabled() {
	if (server_address == NULL) {
	    LOG_F(INFO, "TACACS server address is not available");
	    return false;
	} else {
	    return true;
	}
} 

Status TaccController::Authenticate(const char* user, const char* pass) {
        LOG_F(INFO, "Authentication");
	if(!IsTacacsEnabled()) {
	    return Status(OK, "Returning OK as TACACS server address is not available");
	}

	struct addrinfo *tac_server = NULL;
        struct addrinfo hints;
        memset(&hints, 0, sizeof hints);
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        int ret = getaddrinfo(server_address, "tacacs", &hints, &tac_server);
        if (ret != 0) {
            LOG_F(INFO, "Error: resolving name %s: %s", server_address, gai_strerror(ret));
            return Status(UNAVAILABLE, "Error: resolving name");
        }

        LOG_F(INFO, "Authentication: Connect to the server");
        tac_fd = tac_connect_single(tac_server, secure_key, NULL, 60);
    	if (tac_fd < 0) {
            LOG_F(INFO, "Error connecting to TACACS+ server\n");
            if (fallback_pass){
                return Status(OK, "Returning OK");
            } else {
                return Status(UNAVAILABLE, "Error connecting to TACACS Server");
	    }
    	}

        LOG_F(INFO, "Authentication: Send the authentication request to the server");
    	if (tac_authen_send(tac_fd, user, pass, TAC_FIELD_TTY, remote_addr, TAC_PLUS_AUTHEN_LOGIN) < 0) {
            LOG_F(INFO, "Error sending query to TACACS+ server\n");
            if (fallback_pass){
                return Status(OK, "Returning OK");
            } else {
                return Status(UNAVAILABLE, "Error sending query to TACACS Server");
            }
	}

        LOG_F(INFO, "Authentication: Read the reply from the server");
	struct areply arep;
    	ret = tac_authen_read(tac_fd, &arep);
	if (ret == TAC_PLUS_AUTHEN_STATUS_GETPASS) {
            if (tac_cont_send(tac_fd, pass) < 0) {
	        LOG_F(INFO, "Error sending query to TACACS+ server\n");
                if (fallback_pass){
                    return Status(OK, "Returning OK");
                } else {
                    return Status(UNAVAILABLE, "Error sending query to TACACS Server");
                }
            }
       	    ret = tac_authen_read(tac_fd, &arep);
	}

        LOG_F(INFO, "Authentication: Return value from TACACS server: %d, %s", ret, arep.msg);

    	if (ret == TAC_PLUS_AUTHEN_STATUS_FAIL) {
            LOG_F(INFO, "Authentication FAILED: %s\n", arep.msg);
            return Status(UNAUTHENTICATED, "Authentication FAILED");
    	} else if (ret == TAC_PLUS_AUTHEN_STATUS_PASS) {
            LOG_F(INFO, "Authentication OK\n");
	    close(tac_fd);
            return Status(OK, "Authentication OK");
        } else {
		if (fallback_pass){
		    LOG_F(INFO, "Authentication OK\n");
        	    close(tac_fd);
	            return Status(OK, "Authentication OK");
		} else {
	            LOG_F(INFO, "Authentication FAILED: %s\n", arep.msg);
                    close(tac_fd);
        	    return Status(UNAUTHENTICATED, "Authentication FAILED");
		}
	}
}

Status TaccController::Authorize(const char* user, string methodName) {
        LOG_F(INFO, "Authorize");
        if(!IsTacacsEnabled()) {
            return Status(OK, "Returning OK as TACACS server address is not available");
        }

        struct tac_attrib *attr = NULL;

        tac_add_attrib(&attr, TAC_ATTR_SERVICE, TAC_ATTR_VALUE_SHELL);
	char c[methodName.size() + 1];
        strcpy(c, methodName.c_str());
        tac_add_attrib(&attr, TAC_ATTR_CMD, c);

        struct addrinfo *tac_server = NULL;
        struct addrinfo hints;
        memset(&hints, 0, sizeof hints);
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        int ret = getaddrinfo(server_address, "tacacs", &hints, &tac_server);
        if (ret != 0) {
            LOG_F(INFO, "Error: resolving name %s: %s", server_address, gai_strerror(ret));
            return Status(UNAVAILABLE, "Error: resolving name");
        }

        LOG_F(INFO, "Authorize: Connect to the server");
        tac_fd = tac_connect_single(tac_server, secure_key, NULL, 60);
        if (tac_fd < 0) {
            LOG_F(INFO, "Error connecting to TACACS+ server: %m\n");
            if (fallback_pass){
                return Status(OK, "Returning OK");
            } else {
                return Status(UNAVAILABLE, "Error connecting to TACACS Server");
            }
        }

	struct areply arep;
        LOG_F(INFO, "Authorize: Send the authentication request to the server");
        if (tac_author_send(tac_fd, user, TAC_FIELD_TTY, remote_addr, attr) < 0) {
            LOG_F(INFO, "Error sending authorization query to TACACS+ server\n");
            if (fallback_pass){
                return Status(OK, "Returning OK");
            } else {
                return Status(UNAVAILABLE, "Error sending authorization query to TACACS Server");
            }
        }

        LOG_F(INFO, "Authorize: Read the reply from the server");
        tac_author_read(tac_fd, &arep);

        if (arep.status == AUTHOR_STATUS_PASS_ADD || arep.status == AUTHOR_STATUS_PASS_REPL) {
            LOG_F(INFO, "Authorization OK: %s\n", arep.msg);
            return Status(OK, "Authorization OK");
         } else if (arep.status == AUTHOR_STATUS_FAIL) {
            LOG_F(INFO, "Authorization FAILED: %s\n", arep.msg);
            return Status(PERMISSION_DENIED, "Authorization FAILED");
	 } else {
             if (fallback_pass){
                 LOG_F(INFO, "Authorization OK: %s\n", arep.msg);
                 close(tac_fd);
                 tac_free_attrib(&attr);
                 return Status(OK,"");
              } else {
                  LOG_F(INFO, "Authorization FAILED: %s\n", arep.msg);
                  close(tac_fd);
                  return Status(PERMISSION_DENIED, "Authorization FAILED");
              } 
          }
}

int TaccController::StartAccounting(const char* user, string methodName) {
        LOG_F(INFO, "StartAccounting");
        if(!IsTacacsEnabled()) {
            LOG_F(INFO, "Returning as TACACS server address is not available");
            return 1;
        }

        struct tac_attrib *attr = NULL;
       	int task_id = 0;
       	time_t t = time(0);
	struct tm tm;
	char buf[40];

       	gmtime_r(&t, &tm);
       	strftime(buf, sizeof(buf), "%s", &tm);
       	tac_add_attrib(&attr, TAC_ATTR_START_TIME, buf);

	srand(time(NULL));
       	long rnd_id = rand();
       	memcpy(&task_id, &rnd_id, sizeof(task_id));

       	sprintf(buf, "%hu", task_id);
       	tac_add_attrib(&attr, TAC_ATTR_TASK_ID, buf);
       	tac_add_attrib(&attr, TAC_ATTR_SERVICE, TAC_ATTR_VALUE_SHELL);
	char c[methodName.size() + 1];
        strcpy(c, methodName.c_str());
       	tac_add_attrib(&attr, TAC_ATTR_CMD, c);

        struct addrinfo *tac_server = NULL;
        struct addrinfo hints;
        memset(&hints, 0, sizeof hints);
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        int ret = getaddrinfo(server_address, "tacacs", &hints, &tac_server);
        if (ret != 0) {
            LOG_F(INFO, "Error: resolving name %s: %s", server_address, gai_strerror(ret));
            return -1;
        }

        LOG_F(INFO, "StartAccounting: Connect to the server");
        tac_fd = tac_connect_single(tac_server, secure_key, NULL, 60);
        if (tac_fd < 0) {
            LOG_F(INFO, "Error connecting to TACACS+ server: %m\n");
            return -1;
	}
       	
        LOG_F(INFO, "StartAccounting: Send the start accounting request to the server");
	tac_acct_send(tac_fd, TAC_PLUS_ACCT_FLAG_START, user, TAC_FIELD_TTY, remote_addr, attr);

	struct areply arep;
        LOG_F(INFO, "StartAccounting: Read the reply from the server");
       	ret = tac_acct_read(tac_fd, &arep);
       	if (ret == 0) {
     	    LOG_F(INFO, "Accounting: START failed: %s\n", arep.msg);
	    return -1;
        }

        LOG_F(INFO, "Accounting: START OK\n");
        close(tac_fd);
        tac_free_attrib(&attr);
        return task_id;
}

void TaccController::StopAccounting(const char* user, int task_id, string methodName, string err_msg) {
        LOG_F(INFO, "StopAccounting");
        if(!IsTacacsEnabled()) {
	    LOG_F(INFO, "Returning as TACACS server address is not available");
            return;
        }

        struct tac_attrib *attr = NULL;
       	time_t t = time(0);
	struct tm tm;
	char buf[40];

        gmtime_r(&t, &tm);
        strftime(buf, sizeof(buf), "%s", &tm);
        tac_add_attrib(&attr, TAC_ATTR_STOP_TIME, buf);
        sprintf(buf, "%hu", task_id);
        tac_add_attrib(&attr, TAC_ATTR_TASK_ID, buf);

	if(err_msg != "no error") {
            char c[err_msg.size() + 1];
            strcpy(c, err_msg.c_str());
            tac_add_attrib(&attr, TAC_ATTR_ERR_MSG, c);
            LOG_F(INFO, "StopAccounting: Sending the error msg to the TACACS server");
	}

        struct addrinfo *tac_server = NULL;
        struct addrinfo hints;
        memset(&hints, 0, sizeof hints);
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        int ret = getaddrinfo(server_address, "tacacs", &hints, &tac_server);
        if (ret != 0) {
            LOG_F(INFO, "Error: resolving name %s: %s", server_address, gai_strerror(ret));
            return;
        }

        LOG_F(INFO, "StopAccounting: Connect to the server");
        tac_fd = tac_connect_single(tac_server, secure_key, NULL, 60);
        if (tac_fd < 0) {
            LOG_F(INFO, "Error connecting to TACACS+ server: %m\n");
            return;
        }

        LOG_F(INFO, "StopAccounting: Send the stop accounting request to the server");
        tac_acct_send(tac_fd, TAC_PLUS_ACCT_FLAG_STOP, user, TAC_FIELD_TTY, remote_addr, attr);
	struct areply arep;

        LOG_F(INFO, "StopAccounting: Read the reply from the server");
        ret = tac_acct_read(tac_fd, &arep);
        if (ret == 0) {
            LOG_F(INFO, "Accounting: STOP failed: %s", arep.msg);
	    return;
        }

        LOG_F(INFO, "Accounting: STOP OK\n");
        close(tac_fd);
        tac_free_attrib(&attr);
}	

