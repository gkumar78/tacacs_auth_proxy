/*
 *
 * Copyright 2015 gRPC authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

// Package main implements a client for Greeter service.
package main

import (
        "context"
        "log"
        "flag"
        "encoding/base64"
        "time"

        "google.golang.org/grpc"
        pb "github.com/opencord/voltha-protos/go/openolt"
)

var host, port string
var username, password string

const (
        defaultHost     = "192.168.10.243"
        defaultPort     = "19191"
        defaultUsername = "user1"
        defaultPassword = "voltha"
)

func init() {
        flag.StringVar(&host, "server_host", defaultHost, "Host / IP address of Remote Server")
        flag.StringVar(&port, "server_port", defaultPort, "Listen Port of Remote Server")
        flag.StringVar(&username, "username", defaultUsername, "Username for authentication")
        flag.StringVar(&password, "password", defaultPassword, "Password for authentication")
}

type basicAuthRpcCreds struct {
        user string
        secret string
}

func (cred *basicAuthRpcCreds) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
        res := make(map[string]string)
        credString := cred.user + ":" + cred.secret
        res["Authorization"] = "Basic " + base64.StdEncoding.EncodeToString([]byte(credString))
        return res, nil
}

func (cred *basicAuthRpcCreds) RequireTransportSecurity() bool {
        return false
}

func main() {
        flag.Parse()

        // Set up a connection to the server.
        conn, err := grpc.Dial(host + ":" + port, grpc.WithInsecure(), grpc.WithBlock(), grpc.WithPerRPCCredentials(&basicAuthRpcCreds{user: username, secret: password}))
        if err != nil {
                log.Fatalf("did not connect: %v", err)
        }
        defer conn.Close()

        c := pb.NewOpenoltClient(conn)

        ctx, cancel := context.WithTimeout(context.Background(), time.Second)
        defer cancel()
        r, err := c.DisableOlt(ctx, new(pb.Empty))
        if err != nil {
                log.Fatalf("could not disable olt: %v", err)
        }
        log.Printf("disabled olt: %v", r)
}

