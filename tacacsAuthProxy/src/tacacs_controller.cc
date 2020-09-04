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


class TaccController {

  private:
    char* remote_addr =  "1.1.1.1";
    char* tty = "ttyS0";


  public:
    TaccController(const char* tacacs_server_address, const char* tacacs_secure_key, bool tacacs_fallback_pass){
        server_address = tacacs_server_address;
	secure_key = tacacs_secure_key;
	fallback_pass = tacacs_fallback_pass;
    }
	

    int Authenticate(const char* user, const char* pass) {
        tac_fd = tac_connect_single(tac_server, tac_secret, NULL, 60);
    	if (tac_fd < 0) {
            printf("Error connecting to TACACS+ server: %m\n");
            return Status::NOT_FOUND;
    	}

    	/* start authentication */
    	if (tac_authen_send(tac_fd, user, pass, tty, remote_addr, TAC_PLUS_AUTHEN_LOGIN) < 0) {
            printf("Error sending query to TACACS+ server\n");
            return Status::UNAUTHENTICATED;
    	}

    	ret = tac_authen_read(tac_fd, &arep);
	if (ret == TAC_PLUS_AUTHEN_STATUS_GETPASS) {
            if (tac_cont_send(tac_fd, pass) < 0) {
	        printf("Error sending query to TACACS+ server\n");
                return Status::UNAUTHENTICATED;
            }
       	    ret = tac_authen_read(tac_fd, &arep);
	}

    	if (ret != TAC_PLUS_AUTHEN_STATUS_PASS) {
            printf("Authentication FAILED: %s\n", arep.msg);
            return Status::UNAUTHENTICATED;
    	}

    	printf("Authentication OK\n");
   	    return Status::OK;
    }

    int Authorize(const char* user) {
        struct tac_attrib *attr = NULL;

        tac_add_attrib(&attr, "service", service);
        tac_add_attrib(&attr, "protocol", protocol);

        tac_author_send(tac_fd, user, tty, remote_addr, attr);
        tac_author_read(tac_fd, &arep);

        if (arep.status != AUTHOR_STATUS_PASS_ADD && arep.status != AUTHOR_STATUS_PASS_REPL) {
            printf("Authorization FAILED: %s\n", arep.msg);
            return Status::PERMISSION_DENIED;
        }

        printf("Authorization OK: %s\n", arep.msg);
        tac_free_attrib(&attr);
        return Status::OK;
    }

    int StartAccounting(std:string methodName) {
        struct tac_attrib *attr = NULL;
       	task_id = 0;
       	t = time(0);
       	gmtime_r(&t, &tm);
       	strftime(buf, sizeof(buf), "%s", &tm);
       	tac_add_attrib(&attr, "start_time", buf);

       	// this is not crypto but merely an identifier
       	long rnd_id = random();
       	memcpy(&task_id, &rnd_id, sizeof(task_id));

       	sprintf(buf, "%hu", task_id);
       	tac_add_attrib(&attr, "task_id", buf);
       	tac_add_attrib(&attr, "service", service);
       	tac_add_attrib(&attr, "protocol", protocol);

       	tac_acct_send(tac_fd, TAC_PLUS_ACCT_FLAG_START, user, tty, remote_addr, attr);

       	ret = tac_acct_read(tac_fd, &arep);
       	if (ret == 0) {
     	    printf("Accounting: START failed: %s\n", arep.msg);
	    return Status::INTERNAL;
        }
        printf("Accounting: START OK\n");

        tac_free_attrib(&attr);
    }

    int StopAccounting(std:string methodName) {
        struct tac_attrib *attr = NULL;
        task_id = 0;
        t = time(0);
        gmtime_r(&t, &tm);
        strftime(buf, sizeof(buf), "%s", &tm);
        tac_add_attrib(&attr, "stop_time", buf);
        sprintf(buf, "%hu", task_id);
        tac_add_attrib(&attr, "task_id", buf);

        tac_acct_send(tac_fd, TAC_PLUS_ACCT_FLAG_STOP, user, tty, remote_addr, attr);
        ret = tac_acct_read(tac_fd, &arep);
        if (ret == 0) {
            printf("Accounting: STOP failed: %s", arep.msg);
	    return Status::INTERNAL;
        }
        printf("Accounting: STOP OK\n");

        tac_free_attrib(&attr);
    }	

};
