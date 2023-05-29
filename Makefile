#
#  BSD LICENSE
#
#  Copyright (c) Intel Corporation.
#  All rights reserved.
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions
#  are met:
#
#    * Redistributions of source code must retain the above copyright
#      notice, this list of conditions and the following disclaimer.
#    * Redistributions in binary form must reproduce the above copyright
#      notice, this list of conditions and the following disclaimer in
#      the documentation and/or other materials provided with the
#      distribution.
#    * Neither the name of Intel Corporation nor the names of its
#      contributors may be used to endorse or promote products derived
#      from this software without specific prior written permission.
#
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
#  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
#  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
#  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
#  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
#  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
#  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
#  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
#  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

#
#  This file is part of sci-spdk-nvme-q library.
# 
#  Makefile
# 
#  To build the backend SPDK/NVMe IO interface
# 
#  Part of this file comes from Makefiles in spdk/examples, therefore its
#  associated BSD LICENSE and Copyright Notice is retained as required
#  (see above).
#
#  For details about SPDK please visit https://spdk.io/
#
#  Author: Colin Zhu <czhu@nexnt.com>
#

include ./SSNQ.path

NVME_DIR := $(SPDK_ROOT_DIR)/lib/nvme

include $(SPDK_ROOT_DIR)/mk/spdk.common.mk
include $(SPDK_ROOT_DIR)/mk/spdk.modules.mk

SPDK_NVME := spdk-nvme.so
C_SRCS = spdk_nvme.c

SPDK_LIB_LIST = $(SOCK_MODULES_LIST) nvme vmd

include $(SPDK_ROOT_DIR)/mk/spdk.app_vars.mk

LIBS += $(SPDK_LIB_LINKER_ARGS)

CFLAGS += -Wno-error
LDFLAGS += -fpic -shared -rdynamic -Wl,-z,nodelete

# SSNQ: SCI-SPDK-NVMe-Q
SSNQ := sci-spdk-nvme-q.so
SSNQ_SRCS = sci_spdk_q.c
SSNQ_CFLAGS = -lsyscall_intercept -pthread -lxxhash -fpic -shared -D_GNU_SOURCE
SSNQ_LIBS = $(SPDK_NVME)

# Build HDB Maps
BUILD_HDB_MAPS := ssnq-build-hdb-maps-single-dev.bin
BUILD_HDB_MAPS_SRCS = ssnq-build-hdb-maps-single-dev.c
BUILD_HDB_MAPS_CFLAGS = -lxxhash

CLEAN_FILES = $(SPDK_NVME) $(SSNQ) $(BUILD_HDB_MAPS)

all : $(SPDK_NVME) $(SSNQ) $(BUILD_HDB_MAPS)
	@:

install: empty_rule

uninstall: empty_rule

# To avoid overwriting warning
empty_rule:
	@:

$(SPDK_NVME) : $(OBJS) $(SPDK_LIB_FILES) $(ENV_LIBS)
	$(LINK_C)
	
$(SSNQ) : $(SSNQ_SRCS) $(SSNQ_LIBS)
	$(CC) $(SSNQ_SRCS) $(SSNQ_CFLAGS) -o $(SSNQ) $(SSNQ_LIBS)
	
$(BUILD_HDB_MAPS) : $(BUILD_HDB_MAPS_SRCS)
	$(CC) $^ $(BUILD_HDB_MAPS_CFLAGS) -o $@

clean :
	$(CLEAN_C) $(CLEAN_FILES)

include $(SPDK_ROOT_DIR)/mk/spdk.deps.mk
