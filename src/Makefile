# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
OUTPUT := .output

CLANG ?= clang
CLANG_FORMAT ?= clang-format
LLVM_STRIP ?= llvm-strip
GO ?= go

LIBBPF_SRC := $(abspath ../libbpf/src)
LIBBPF_OBJ := $(abspath $(OUTPUT)/libbpf.a)

BPFTOOL_SRC := $(abspath ../bpftool/src)
BPFTOOL_OUTPUT ?= $(abspath $(OUTPUT)/bpftool)
BPFTOOL ?= $(BPFTOOL_OUTPUT)/bootstrap/bpftool

ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
BTFFILE = /sys/kernel/btf/vmlinux
VMLINUX := ../vmlinux/$(ARCH)/vmlinux.h

# Use our own libbpf API headers and Linux UAPI headers distributed with
# libbpf to avoid dependency on system-wide headers, which could be missing or
# outdated
INCLUDES := -I$(OUTPUT) -I../../libbpf/include/uapi -I$(dir $(VMLINUX))
CFLAGS := -g -Wall
ALL_LDFLAGS := $(LDFLAGS) $(EXTRA_LDFLAGS)

.PHONY: all
all: bootstrap

.PHONY: clean
clean:
	$(Q)rm -rf $(OUTPUT) bootstrap.bpf.o bootstrap

$(OUTPUT) $(OUTPUT)/libbpf $(BPFTOOL_OUTPUT):
	$(Q)mkdir -p $@

# Build libbpf
$(LIBBPF_OBJ): $(wildcard $(LIBBPF_SRC)/*.[ch] $(LIBBPF_SRC)/Makefile) | $(OUTPUT)/libbpf
	$(Q)$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1 \
		OBJDIR=$(dir $@)/libbpf DESTDIR=$(dir $@)    \
		INCLUDEDIR= LIBDIR= UAPIDIR=                 \
		install

# Build bpftool
$(BPFTOOL): | $(BPFTOOL_OUTPUT)
	$(Q)$(MAKE) ARCH= CROSS_COMPILE= OUTPUT=$(BPFTOOL_OUTPUT)/ -C $(BPFTOOL_SRC) bootstrap

# Build BPF code
bootstrap.bpf.o: bootstrap.bpf.c $(LIBBPF_OBJ) | $(OUTPUT)
	$(Q)$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) -c bootstrap.bpf.c -o $@
	$(Q)$(LLVM_STRIP) -g $@

# Build application binary
bootstrap: bootstrap.bpf.o bootstrap.go
	$(Q)$(GO) build -o $@ bootstrap.go

.PHONY: $(VMLINUX)
$(VMLINUX): $(BPFTOOL)
	$(Q)$(BPFTOOL) btf dump file $(BTFFILE) format c > $(VMLINUX)

.PHONY: format
format:
	$(Q)$(CLANG_FORMAT) --verbose -i \
	bootstrap.bpf.c \
	bootstrap.h

# delete failed targets
.DELETE_ON_ERROR:

# keep intermediate (.bpf.o, etc) targets
.SECONDARY:
