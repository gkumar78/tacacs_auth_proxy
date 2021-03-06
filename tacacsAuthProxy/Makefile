#Copyright 2018-present Open Networking Foundation
#
#Licensed under the Apache License, Version 2.0 (the "License");
#you may not use this file except in compliance with the License.
#You may obtain a copy of the License at
#
#http://www.apache.org/licenses/LICENSE-2.0
#
#Unless required by applicable law or agreed to in writing, software
#distributed under the License is distributed on an "AS IS" BASIS,
#WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#See the License for the specific language governing permissions and
#limitations under the License.

########################################################################

TOP_DIR=`pwd`
# Build directory
BUILD_DIR = build

OPENOLT_PROTO_VER ?= v3.4.5

# Protobuf installation
PROTOBUF_VER ?= 3.5.0
PROTOBUF_ADDR = https://github.com/protocolbuffers/protobuf/releases/download/v$(PROTOBUF_VER)/protobuf-cpp-$(PROTOBUF_VER).tar.gz
PROTOBUF_DST = /tmp/protobuf-$(PROTOBUF_VER)
protoc-bin = /usr/local/bin/protoc

# Libtac installation
LIBTAC_VER = v1.4.1
LIBTAC_ADDR = https://github.com/kravietz/pam_tacplus.git
LIBTAC_DST = /tmp/libtac-$(LIBTAC_VER)
tacc-bin = /usr/local/bin/tacc

# GRPC installation
GRPC_ADDR = https://github.com/grpc/grpc
GRPC_DST = /tmp/grpc
GRPC_VER = v1.10.x
grpc-cpp-plugin-bin = /usr/local/bin/grpc_cpp_plugin

USER := $(shell echo $(USER))
#
########################################################################
##
##
##        Install prerequisites
##
##
HOST_SYSTEM = $(shell uname | cut -f 1 -d_)
SYSTEM ?= $(HOST_SYSTEM)

VERSION ?= 1.0.0

#set ref and commit date only if committed
LABEL_VCS_URL       ?= $(shell git remote get-url $(shell git remote))
LABEL_VCS_REF       = $(shell git rev-parse HEAD)
LABEL_BUILD_DATE    ?= $(shell date -u "+%Y-%m-%dT%H:%M:%SZ")
LABEL_COMMIT_DATE   = $(shell git show -s --format=%cd --date=iso-strict HEAD)

LIBGRPC_PATH=$(shell pkg-config --libs-only-L grpc | sed s/-L// | sed s/\ //g)
LIBPROTOBUF_PATH=$(shell PKG_CONFIG_ALLOW_SYSTEM_LIBS=true pkg-config --libs-only-L protobuf | sed s/-L// | sed s/\ //g)
LIBTACPLUS_PATH=$(shell pkg-config --libs-only-L libtac | sed s/-L// | sed s/\ //g)

CXX = g++-4.9
CXXFLAGS += -g -O2
#CXXFLAGS += $(shell pkg-config --cflags-only-I grpc++) -Wl,--unresolved-symbols=ignore-all
CXXFLAGS += $(shell pkg-config --cflags-only-I grpc++)
CPPFLAGS += 
CPPFLAGS += `pkg-config --cflags protobuf grpc`
CPPFLAGS += -DVERSION=\"$(VERSION)\" -DLABEL_VCS_URL=\"$(LABEL_VCS_URL)\" \
            -DLABEL_VCS_REF=\"$(LABEL_VCS_REF)\" -DLABEL_BUILD_DATE=\"$(LABEL_BUILD_DATE)\" \
            -DLABEL_COMMIT_DATE=\"$(LABEL_COMMIT_DATE)\" -DFLOW_CHECKER
CPPFLAGS += -I./
CXXFLAGS += -std=c++11 -fpermissive -Wno-literal-suffix -DTEST_MODE -DENABLE_LOG -DCARES_STATICLIB -pthread -I/usr/local/include
LDFLAGS += 
LDFLAGS += `pkg-config --libs protobuf grpc++ grpc libtac` -ldl -lgpr -lpthread -lcrypto -lssl -Wl,--unresolved-symbols=ignore-all
#LDFLAGS += `pkg-config --libs protobuf grpc++ grpc libtac` -ldl -lgpr -lpthread -lcrypto -lssl

export CXX CXXFLAGS OPENOLT_PROTO_VER

.DEFAULT_GOAL := all

prereqs-system:
	sudo apt-get -q -y install git pkg-config build-essential autoconf libtool libgflags-dev libgtest-dev clang unzip docker.io
	sudo apt-get install -y build-essential autoconf libssl-dev gawk debhelper dh-systemd init-system-helpers curl cmake ccache g++-4.9 cpp-4.9
	sudo apt-get install -y libpam-tacplus automake libpam-dev libssl-dev

prereqs-local: $(protoc-bin) $(grpc-cpp-plugin-bin) $(tacc-bin)

$(protoc-bin):
	# Install protobuf
	rm -rf $(PROTOBUF_DST)
	cd /tmp && wget $(PROTOBUF_ADDR)
	cd /tmp && tar -zxvf protobuf-cpp-$(PROTOBUF_VER).tar.gz
	cd $(PROTOBUF_DST) && ./autogen.sh
	cd $(PROTOBUF_DST) && ./configure
	make -C $(PROTOBUF_DST)
	sudo make -C $(PROTOBUF_DST) install
	# Need to create symlink for grpc
	sudo ln -sf /usr/local/lib/libprotobuf.so.15 /usr/lib/libprotobuf.so.15
	sudo ln -sf /usr/local/lib/libprotoc.so.15 /usr/lib/libprotoc.so.15

$(tacc-bin):
	# Install libtac
	rm -rf $(LIBTAC_DST)
	cd /tmp && git clone -b $(LIBTAC_VER) $(LIBTAC_ADDR) $(LIBTAC_DST)
	cd $(LIBTAC_DST) && autoreconf -i
	cd $(LIBTAC_DST) && ./configure
	make -C $(LIBTAC_DST)
	sudo make -C $(LIBTAC_DST) install

$(grpc-cpp-plugin-bin):
	# Install GRPC, protoc
	rm -rf $(GRPC_DST)
	cd /tmp && git clone -b $(GRPC_VER) $(GRPC_ADDR) $(GRPC_DST)
	cd $(GRPC_DST) && git submodule update --init
	make -C $(GRPC_DST)
	sudo make -C $(GRPC_DST) install

prereqs-local-clean:
	make -C $(GRPC_DST) clean
	make -C $(PROTOBUF_DST) clean
	make -C $(LIBTAC_DST) clean
	

########################################################################
##
##
##        OpenOLT API
##
##
OPENOLT_PROTOS_DIR = ../protos
OPENOLT_API_LIB = $(OPENOLT_PROTOS_DIR)/libopenoltapi.a
CXXFLAGS += -I$(OPENOLT_PROTOS_DIR) -I$(OPENOLT_PROTOS_DIR)/googleapis/gens
protos:
	make -C $(OPENOLT_PROTOS_DIR) all
protos-clean:
	make -C $(OPENOLT_PROTOS_DIR) clean
	rm -rf $(OPENOLT_PROTOS_DIR)/googleapis

########################################################################
##
##
##        tacacs-auth-proxy
##
##
SRCS = $(wildcard src/*.cc) 
OBJS = $(SRCS:.cc=.o)
DEPS = $(SRCS:.cc=.d)
$(BUILD_DIR)/tacacsproxy: prereqs-local $(OBJS)
	mkdir -p $(BUILD_DIR)
	$(CXX) $(OBJS) $(OPENOLT_API_LIB) $(LIBPROTOBUF_PATH)/libprotobuf.a -o $@ $(LDFLAGS)
	ln -sf $(LIBPROTOBUF_PATH)/libprotobuf.so.15 $(BUILD_DIR)/libprotobuf.so.15
	ln -sf $(LIBGRPC_PATH)/libgrpc.so.6 $(BUILD_DIR)/libgrpc.so.6
	ln -sf $(LIBGRPC_PATH)/libgpr.so.6 $(BUILD_DIR)/libgpr.so.6
	ln -sf $(LIBGRPC_PATH)/libgrpc++.so.1 $(BUILD_DIR)/libgrpc++.so.1
	ln -sf /usr/lib/x86_64-linux-gnu/libstdc++.so.6 $(BUILD_DIR)/libstdc++.so.6
	ln -sf $(LIBTACPLUS_PATH)/libtac.so.2 $(BUILD_DIR)/libtac.so.2
	strip $(BUILD_DIR)/tacacsproxy

all: $(BUILD_DIR)/tacacsproxy

deb:
	cp $(BUILD_DIR)/tacacsproxy device/mkdebian/debian
	cp $(BUILD_DIR)/libprotobuf.so.15 device/mkdebian/debian
	cp $(BUILD_DIR)/libgrpc.so.6 device/mkdebian/debian
	cp $(BUILD_DIR)/libgpr.so.6 device/mkdebian/debian
	cp $(BUILD_DIR)/libgrpc++.so.1 device/mkdebian/debian
	cp $(BUILD_DIR)/libstdc++.so.6 device/mkdebian/debian
	cp $(BUILD_DIR)/libtac.so.2 device/mkdebian/debian
	cp -a scripts/init.d device/mkdebian/debian
	cp -a scripts/config device/mkdebian/debian
	cd device/mkdebian && ./build_deb.sh
	mv device/*.deb $(BUILD_DIR)/tacacs-auth-proxy_$(VERSION).deb
	make deb-cleanup

deb-cleanup:
	rm -rf device/mkdebian/debian/tacacsproxy
	rm -rf device/mkdebian/debian/libprotobuf.so.15
	rm -rf device/mkdebian/debian/libgrpc.so.6
	rm -rf device/mkdebian/debian/libgpr.so.6
	rm -rf device/mkdebian/debian/libgrpc++.so.1
	rm -rf device/mkdebian/debian/libstdc++.so.6
	rm -rf device/mkdebian/debian/libtac.so.2
	rm -rf device/mkdebian/debian/init.d/
	rm -rf device/mkdebian/debian/config/
	rm -rf device/mkdebian/debian/tmp/
	rm -rf device/mkdebian/debian/tacacs-auth-proxy/

clean:
	rm -f $(OBJS) $(DEPS)
	rm -f $(BUILD_DIR)/libprotobuf.so.15
	rm -f $(BUILD_DIR)/libgrpc.so.6 $(BUILD_DIR)/libgrpc++.so.1 
	rm -f $(BUILD_DIR)/libgpr.so.6 
	rm -f $(BUILD_DIR)/libstdc++.so.6 $(BUILD_DIR)/libtac.so.2
	rm -f $(BUILD_DIR)/tacacsproxy
	rm -f $(BUILD_DIR)/tacacs-auth-proxy-$(VERSION).deb

clean-src: protos-clean
	rm -f $(OBJS) $(DEPS)

distclean: clean-src clean prereqs-local-clean
	rm -rf $(BUILD_DIR)

.PHONY: protos prereqs-system prereqs-local .FORCE
