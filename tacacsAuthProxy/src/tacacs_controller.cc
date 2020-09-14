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
}

bool TaccController::IsTacacsEnabled() {
    if (server_address == NULL) {
        LOG_F(MAX, "TACACS server address is not available");
        return false;
    } else {
        return true;
    }
} 

struct addrinfo* TaccController::ResolveServerAddress() {
    if(resolved_server_address != NULL) {
        return resolved_server_address;
    }

    struct addrinfo *tac_server = NULL;
    struct addrinfo hints;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    string s(server_address);
    int pos = s.find(":");
    string host, port;
    if (pos > 0){
        port = s.substr(pos + 1);
        host = s.substr(0,pos);
    } else {
        host = s;
        port = "49";
    }
    int ret = getaddrinfo(host.c_str(), port.c_str(), &hints, &tac_server);
    if (ret != 0) {
        LOG_F(WARNING, "Error: resolving name %s: %s", server_address, gai_strerror(ret));
        return NULL;
    }

    resolved_server_address = tac_server;
    return tac_server;
}

Status TaccController::Authenticate(TacacsContext* tacCtx) {
    LOG_F(MAX, "Authentication");
    if(!IsTacacsEnabled() || tacCtx->tacacs_connect_failure) {
        return Status(OK, "Returning OK as TACACS server is not available");
    }

    if (ResolveServerAddress() == NULL) {
        if (fallback_pass){
            return Status(OK, "Returning OK");
        } else {
            return Status(UNAVAILABLE, "Error connecting to TACACS Server");
        }
    }

    LOG_F(MAX, "Authentication: Connect to the server");
    tac_fd = tac_connect_single(resolved_server_address, secure_key, NULL, 60);
    if (tac_fd < 0) {
        LOG_F(WARNING, "Error connecting to TACACS+ server");
        tacCtx->tacacs_connect_failure = true;
        if (fallback_pass){
            return Status(OK, "Returning OK");
        } else {
            return Status(UNAVAILABLE, "Error connecting to TACACS Server");
        }
    }

    LOG_F(MAX, "Authentication: Send the authentication request to the server");
    if (tac_authen_send(tac_fd, tacCtx->getUsername(), tacCtx->getPassword(), TAC_FIELD_TTY, tacCtx->getRemoteAddr(), TAC_PLUS_AUTHEN_LOGIN) < 0) {
        LOG_F(WARNING, "Error sending query to TACACS+ server");
        if (fallback_pass){
            return Status(OK, "Returning OK");
        } else {
            return Status(UNAVAILABLE, "Error sending query to TACACS Server");
        }
    }

    LOG_F(MAX, "Authentication: Read the reply from the server");
    struct areply arep;
    int ret = tac_authen_read(tac_fd, &arep);
    if (ret == TAC_PLUS_AUTHEN_STATUS_GETPASS) {
        if (tac_cont_send(tac_fd, tacCtx->getPassword()) < 0) {
            LOG_F(WARNING, "Error sending query to TACACS+ server");
            if (fallback_pass){
                return Status(OK, "Returning OK");
            } else {
                return Status(UNAVAILABLE, "Error sending query to TACACS Server");
            }
        }
        ret = tac_authen_read(tac_fd, &arep);
    }

    LOG_F(MAX, "Authentication: Return value from TACACS server: %d, %s", ret, arep.msg);

    if (ret == TAC_PLUS_AUTHEN_STATUS_FAIL) {
        LOG_F(INFO, "Authentication FAILED: %s", arep.msg);
        return Status(UNAUTHENTICATED, "Authentication FAILED");
    } else if (ret == TAC_PLUS_AUTHEN_STATUS_PASS) {
        LOG_F(INFO, "Authentication OK");
        close(tac_fd);
        return Status(OK, "Authentication OK");
    } else {
        if (fallback_pass){
            LOG_F(INFO, "Authentication OK in Fallback mode");
            close(tac_fd);
            return Status(OK, "Authentication OK");
        } else {
            LOG_F(INFO, "Authentication FAILED in Fallback mode");
            close(tac_fd);
            return Status(UNAUTHENTICATED, "Authentication FAILED");
        }
    }
}

Status TaccController::Authorize(TacacsContext* tacCtx) {
    LOG_F(MAX, "Authorize");
    if(!IsTacacsEnabled() || tacCtx->tacacs_connect_failure) {
        return Status(OK, "Returning OK as TACACS server is not available");
    }

    struct tac_attrib *attr = NULL;

    tac_add_attrib(&attr, TAC_ATTR_SERVICE, TAC_ATTR_VALUE_SHELL);
    char c[tacCtx->method_name.size() + 1];
    strcpy(c, tacCtx->getMethodName());
    tac_add_attrib(&attr, TAC_ATTR_CMD, c);

    if (ResolveServerAddress() == NULL) {
        if (fallback_pass){
            return Status(OK, "Returning OK");
        } else {
            return Status(UNAVAILABLE, "Error connecting to TACACS Server");
        }
    }

    LOG_F(MAX, "Authorize: Connect to the server");
    tac_fd = tac_connect_single(resolved_server_address, secure_key, NULL, 60);
    if (tac_fd < 0) {
        LOG_F(WARNING, "Error connecting to TACACS+ server");
        tacCtx->tacacs_connect_failure = true;
        if (fallback_pass){
            return Status(OK, "Returning OK");
        } else {
            return Status(UNAVAILABLE, "Error connecting to TACACS Server");
        }
    }

    struct areply arep;
    LOG_F(MAX, "Authorize: Send the authentication request to the server");
    if (tac_author_send(tac_fd, tacCtx->getUsername(), TAC_FIELD_TTY, tacCtx->getRemoteAddr(), attr) < 0) {
        LOG_F(INFO, "Error sending authorization query to TACACS+ server");
        if (fallback_pass){
            return Status(OK, "Returning OK");
        } else {
            return Status(UNAVAILABLE, "Error sending authorization query to TACACS Server");
        }
    }

    LOG_F(MAX, "Authorize: Read the reply from the server");
    tac_author_read(tac_fd, &arep);

    if (arep.status == AUTHOR_STATUS_PASS_ADD || arep.status == AUTHOR_STATUS_PASS_REPL) {
        LOG_F(INFO, "Authorization OK: %s", arep.msg);
        return Status(OK, "Authorization OK");
    } else if (arep.status == AUTHOR_STATUS_FAIL) {
        LOG_F(INFO, "Authorization FAILED: %s", arep.msg);
        return Status(PERMISSION_DENIED, "Authorization FAILED");
    } else {
        if (fallback_pass){
            LOG_F(INFO, "Authorization OK in Fallback mode");
            close(tac_fd);
            tac_free_attrib(&attr);
            return Status(OK,"");
        } else {
            LOG_F(INFO, "Authorization FAILED in Fallback mode");
            close(tac_fd);
            return Status(PERMISSION_DENIED, "Authorization FAILED");
        } 
    }
}

void TaccController::StartAccounting(TacacsContext* tacCtx) {
    LOG_F(MAX, "StartAccounting");
    if(!IsTacacsEnabled()) {
        LOG_F(INFO, "Bypassing Accounting as TACACS server is not available");
        return;
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
    char c[tacCtx->method_name.size() + 1];
    strcpy(c, tacCtx->getMethodName());
    tac_add_attrib(&attr, TAC_ATTR_CMD, c);

    tacCtx->task_id = task_id;
    tacCtx->start_time = t;

    if (ResolveServerAddress() == NULL) {
        return;
    }

    LOG_F(MAX, "StartAccounting: Connect to the server");
    tac_fd = tac_connect_single(resolved_server_address, secure_key, NULL, 60);
    if (tac_fd < 0) {
	tacCtx->tacacs_connect_failure = true;
        LOG_F(WARNING, "Error connecting to TACACS+ server");
        return;
    }

    LOG_F(MAX, "StartAccounting: Send the start accounting request to the server");
    tac_acct_send(tac_fd, TAC_PLUS_ACCT_FLAG_START, tacCtx->getUsername(), TAC_FIELD_TTY, tacCtx->getRemoteAddr(), attr);

    struct areply arep;
    LOG_F(MAX, "StartAccounting: Read the reply from the server");
    int ret = tac_acct_read(tac_fd, &arep);
    if (ret == 0) {
        LOG_F(INFO, "Accounting: START failed: %s", arep.msg);
        return;
    }

    LOG_F(INFO, "Accounting: START OK");
    close(tac_fd);
    tac_free_attrib(&attr);
}

void TaccController::StopAccounting(TacacsContext* tacCtx, string err_msg) {
    LOG_F(MAX, "StopAccounting");
    if(!IsTacacsEnabled()) {
        LOG_F(MAX, "Bypassing Accounting as TACACS server is not available");
        return;
    }

    struct tac_attrib *attr = NULL;
    time_t t = time(0);
    struct tm tm;
    char buf[40];

    gmtime_r(&t, &tm);
    strftime(buf, sizeof(buf), "%s", &tm);
    tac_add_attrib(&attr, TAC_ATTR_STOP_TIME, buf);
    int elapsed_sec = t - tacCtx->start_time;
    sprintf(buf, "%hu", elapsed_sec);
    tac_add_attrib(&attr, TAC_ATTR_ELAPSED_TIME, buf);
    sprintf(buf, "%hu", tacCtx->task_id);
    tac_add_attrib(&attr, TAC_ATTR_TASK_ID, buf);

    if(err_msg != "no error") {
        char c[err_msg.size() + 1];
        strcpy(c, err_msg.c_str());
        tac_add_attrib(&attr, TAC_ATTR_ERR_MSG, c);
        LOG_F(INFO, "StopAccounting: Sending error msg as %s", err_msg.c_str());
    }

    if (ResolveServerAddress() == NULL) {
        return;
    }

    LOG_F(MAX, "StopAccounting: Connect to the server");
    tac_fd = tac_connect_single(resolved_server_address, secure_key, NULL, 60);
    if (tac_fd < 0) {
        tacCtx->tacacs_connect_failure = true;
        LOG_F(WARNING, "Error connecting to TACACS+ server");
        return;
    }

    LOG_F(MAX, "StopAccounting: Send the stop accounting request to the server");
    tac_acct_send(tac_fd, TAC_PLUS_ACCT_FLAG_STOP, tacCtx->getUsername(), TAC_FIELD_TTY, tacCtx->getRemoteAddr(), attr);
    struct areply arep;

    LOG_F(MAX, "StopAccounting: Read the reply from the server");
    int ret = tac_acct_read(tac_fd, &arep);
    if (ret == 0) {
        LOG_F(WARNING, "Accounting: STOP failed: %s", arep.msg);
        return;
    }

    LOG_F(INFO, "Accounting: STOP OK");
    close(tac_fd);
    tac_free_attrib(&attr);
}    

