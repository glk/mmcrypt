all: mmcrypt-test

CFLAGS?= -Wall -march=native -g -O2 -funroll-loops -fomit-frame-pointer -fno-strict-aliasing
# CFLAGS?= -Wall -O0 -g

ifdef DEBUG
CFLAGS:= $(CFLAGS) -DMMCRYPT_DEBUG
endif

OBJS_KECCAK_COMMON:= KeccakSponge.o KeccakDuplex.o
OBJS_KECCAK_REF:= KeccakF-1600-reference.o
OBJS_KECCAK_OPT_32:= KeccakF-1600-opt32.o
OBJS_KECCAK_OPT_64:= KeccakF-1600-opt64.o
OBJS_KECCAK_OPT_64_ASM:= KeccakF-1600-x86-64-asm.o KeccakF-1600-x86-64-gas.o

ifeq ($(KECCAK), ref)
OBJS_KECCAK:= $(OBJS_KECCAK_COMMON) $(OBJS_KECCAK_REF)
else ifeq ($(KECCAK), opt-64)
OBJS_KECCAK:= $(OBJS_KECCAK_COMMON) $(OBJS_KECCAK_OPT_64)
else ifeq ($(KECCAK), opt-64-asm)
OBJS_KECCAK:= $(OBJS_KECCAK_COMMON) $(OBJS_KECCAK_OPT_64_ASM)
else
OBJS_KECCAK:= $(OBJS_KECCAK_COMMON) $(OBJS_KECCAK_OPT_32)
endif

OBJS_MMCRYPT:= mmcrypt.o
OBJS_MMCRYPT_TEST:= mmcrypt-test.o
OBJS_KECCAK_ALL:= $(OBJS_KECCAK_COMMON) $(OBJS_KECCAK_REF) $(OBJS_KECCAK_OPT_32) $(OBJS_KECCAK_OPT_64) $(OBJS_KECCAK_OPT_64_ASM)
OBJS_ALL:= $(OBJS_KECCAK_ALL) $(OBJS_MMCRYPT) $(OBJS_MMCRYPT_TEST)

mmcrypt-test: $(OBJS_KECCAK) $(OBJS_MMCRYPT) $(OBJS_MMCRYPT_TEST)
	$(CC) $(CFLAGS) $^ -o $@

.PHONY: clean
clean:
	rm -f $(OBJS_ALL) mmcrypt-test
