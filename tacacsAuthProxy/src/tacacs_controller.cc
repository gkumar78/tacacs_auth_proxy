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

TaccController::TaccController(const char* tacacs_server_address, const char* tacacs_secure_key, bool tacacs_fallback_pass){
        server_address = tacacs_server_address;
	secure_key = tacacs_secure_key;
	fallback_pass = tacacs_fallback_pass;
	remote_addr =  "1.1.1.1";
	tty =  "ttyS0";
    }
	

Status TaccController::Authenticate(const char* user, const char* pass) {
        LOG_F(INFO, "Authentication");
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

        tac_fd = tac_connect_single(tac_server, secure_key, NULL, 60);
    	if (tac_fd < 0) {
            LOG_F(INFO, "Error connecting to TACACS+ server: %m\n");
            return Status(UNAVAILABLE, "Error connecting to TACACS Server");
    	}

    	/* start authentication */
    	if (tac_authen_send(tac_fd, user, pass, tty, remote_addr, TAC_PLUS_AUTHEN_LOGIN) < 0) {
            LOG_F(INFO, "Error sending query to TACACS+ server\n");
            return Status(UNAVAILABLE, "Error sending query to TACACS Server"); 
    	}

	struct areply arep;
    	ret = tac_authen_read(tac_fd, &arep);
	if (ret == TAC_PLUS_AUTHEN_STATUS_GETPASS) {
            if (tac_cont_send(tac_fd, pass) < 0) {
	        LOG_F(INFO, "Error sending query to TACACS+ server\n");
                return Status(UNAVAILABLE, "Error sending query to TACACS+ server");
            }
       	    ret = tac_authen_read(tac_fd, &arep);
	}

    	if (ret != TAC_PLUS_AUTHEN_STATUS_PASS) {
            LOG_F(INFO, "Authentication FAILED: %s\n", arep.msg);
            return Status(UNAUTHENTICATED, "Authentication FAILED");
    	}

    	LOG_F(INFO, "Authentication OK\n");
	close(tac_fd);
   	return Status(OK, "");
    }

Status TaccController::Authorize(const char* user, string methodName) {
        LOG_F(INFO, "Authorize");
        struct tac_attrib *attr = NULL;

        tac_add_attrib(&attr, "service", "shell");
	char c[methodName.size() + 1];
        strcpy(c, methodName.c_str());
        tac_add_attrib(&attr, "cmd", c);
        //tac_add_attrib(&attr, "protocol", "ip");


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
        tac_fd = tac_connect_single(tac_server, secure_key, NULL, 60);
        if (tac_fd < 0) {
            LOG_F(INFO, "Error connecting to TACACS+ server: %m\n");
            return Status(UNAVAILABLE, "Error connecting to TACACS Server");
        }

	struct areply arep;
        LOG_F(INFO, "Authorize msg send");
        if (tac_author_send(tac_fd, user, tty, remote_addr, attr) < 0) {
            LOG_F(INFO, "Error sending authorization query to TACACS+ server\n");
            return Status(UNAVAILABLE, "Error sending authorization query to TACACS Server");
        }

        LOG_F(INFO, "Authorize reply received");
        tac_author_read(tac_fd, &arep);

        if (arep.status != AUTHOR_STATUS_PASS_ADD && arep.status != AUTHOR_STATUS_PASS_REPL) {
            LOG_F(INFO, "Authorization FAILED: %s\n", arep.msg);
            return Status(PERMISSION_DENIED, "Authorization FAILED");
        }

        LOG_F(INFO, "Authorization OK: %s\n", arep.msg);
        tac_free_attrib(&attr);
        close(tac_fd);
        return Status(OK,"");
    }

int TaccController::StartAccounting(const char* user, string methodName) {
        struct tac_attrib *attr = NULL;
       	int task_id = 0;
       	time_t t = time(0);
	struct tm tm;
	char buf[40];

       	gmtime_r(&t, &tm);
       	strftime(buf, sizeof(buf), "%s", &tm);
       	tac_add_attrib(&attr, "start_time", buf);

       	// this is not crypto but merely an identifier
       	long rnd_id = random();
       	memcpy(&task_id, &rnd_id, sizeof(task_id));

       	sprintf(buf, "%hu", task_id);
       	tac_add_attrib(&attr, "task_id", buf);
       	tac_add_attrib(&attr, "service", "shell");
	char c[methodName.size() + 1];
        strcpy(c, methodName.c_str());
       	tac_add_attrib(&attr, "cmd", c);

       	tac_acct_send(tac_fd, TAC_PLUS_ACCT_FLAG_START, user, tty, remote_addr, attr);

	struct areply arep;
       	int ret = tac_acct_read(tac_fd, &arep);
       	if (ret == 0) {
     	    LOG_F(INFO, "Accounting: START failed: %s\n", arep.msg);
	    return -1;
        }
        LOG_F(INFO, "Accounting: START OK\n");

        tac_free_attrib(&attr);
        return task_id;
    }

void TaccController::StopAccounting(const char* user, int task_id, string methodName) {
        struct tac_attrib *attr = NULL;
       	time_t t = time(0);
	struct tm tm;
	char buf[40];

        gmtime_r(&t, &tm);
        strftime(buf, sizeof(buf), "%s", &tm);
        tac_add_attrib(&attr, "stop_time", buf);
        sprintf(buf, "%hu", task_id);
        tac_add_attrib(&attr, "task_id", buf);

        tac_acct_send(tac_fd, TAC_PLUS_ACCT_FLAG_STOP, user, tty, remote_addr, attr);
	struct areply arep;
        int ret = tac_acct_read(tac_fd, &arep);
        if (ret == 0) {
            LOG_F(INFO, "Accounting: STOP failed: %s", arep.msg);
	    return;
        }
        LOG_F(INFO, "Accounting: STOP OK\n");

        tac_free_attrib(&attr);
    }	

