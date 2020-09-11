#!/bin/bash

SCRIPTDIR=`dirname $0 | pwd`
TACACS_SERVER_ADDRESS=192.168.10.243
TACACS_SECURE_KEY=tacacs
TACACS_FALLBACK_PASS=0
INTERFACE_ADDRESS=192.168.10.243:19191
OPENOLT_AGENT_ADDRESS=192.168.10.243:50060

[ -z "$TACACS_SERVER_ADDRESS" ] || APPARGS="--tacacs_server_address $TACACS_SERVER_ADDRESS"
[ -z "$TACACS_SECURE_KEY" ] || APPARGS="$APPARGS --tacacs_secure_key $TACACS_SECURE_KEY"
[ -z "$TACACS_FALLBACK_PASS" ] || APPARGS="$APPARGS --tacacs_fallback_pass $TACACS_FALLBACK_PASS"
[ -z "$INTERFACE_ADDRESS" ] || APPARGS="$APPARGS --interface_address $INTERFACE_ADDRESS"
[ -z "$OPENOLT_AGENT_ADDRESS" ] || APPARGS="$APPARGS --openolt_agent_address $OPENOLT_AGENT_ADDRESS"

$SCRIPTDIR/build/tacacsproxy $APPARGS $@
