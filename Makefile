# SPDX-License-Identifier: GPL-2.0

AS	= bpf-unknown-none-as
CLANG	= clang
OBJDUMP	= llvm-objdump
RM	= rm -f

BPF_TARGET	?= bpf
BPF_ASFLAGS	?=
BPF_CLANGFLAGS	?= -target $(BPF_TARGET) -Wall -Werror -x assembler-with-cpp

SRCS	:= $(wildcard bpf/*.S)
PROGS	:= $(SRCS:.S=.o)

all: $(PROGS)

ifeq ($(LLVM),1)
%.o: %.S
	$(CLANG) $(BPF_CLANGFLAGS) -c $< -o $@
else
%.o: %.S
	$(AS) $(BPF_ASFLAGS) -o $@ $<
endif

dump: $(PROGS)
	$(OBJDUMP) -d $(PROGS)

check-tools:
	@command -v $(AS) >/dev/null || echo "missing: $(AS)"
	@command -v $(CLANG) >/dev/null || echo "missing: $(CLANG)"
	@command -v $(OBJDUMP) >/dev/null || echo "missing: $(OBJDUMP)"

clean:
	$(RM) $(PROGS)

.PHONY: all clean dump check-tools
