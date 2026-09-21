CLANG   ?= clang
BPFTOOL ?= bpftool
CC      ?= gcc
ARCH    := x86

BPF_SRC  := bpf/netpath.bpf.c
BPF_OBJ  := bpf/netpath.bpf.o
VMLINUX  := bpf/vmlinux.h
SKEL     := src/netpath.skel.h
USR_SRC  := src/netpath.c
BIN      := netpath

.PHONY: all clean

all: $(BIN)

$(VMLINUX):
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX)

$(BPF_OBJ): $(BPF_SRC) $(VMLINUX) common.h
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
		-I. -Ibpf \
		-c $(BPF_SRC) -o $(BPF_OBJ)

$(SKEL): $(BPF_OBJ)
	$(BPFTOOL) gen skeleton $(BPF_OBJ) > $(SKEL)

$(BIN): $(SKEL) $(USR_SRC) common.h
	$(CC) -g -O2 -Isrc -o $(BIN) $(USR_SRC) -lbpf -lelf -lz

clean:
	rm -f $(BPF_OBJ) $(SKEL) $(BIN) $(VMLINUX)
