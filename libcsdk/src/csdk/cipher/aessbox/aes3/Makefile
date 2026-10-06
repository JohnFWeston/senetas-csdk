CC ?= gcc
# Optimize for modern Intel; users can still override CFLAGS externally
CFLAGS ?= -O3 -Wall -Wextra -std=c11 -fomit-frame-pointer -fno-asynchronous-unwind-tables -march=native -mtune=native -falign-functions=32 -falign-loops=32

ASM  = aes-x86_64.s cpuid.s
TE_INC = Te_words.inc
TD_INC = Td_words.inc

all: test_aes

# Generate S-box include files (default S-box unless stdin provided)
gen_sbox: gen_sbox.c
	$(CC) $(CFLAGS) $< -o $@

$(TE_INC) $(TD_INC): gen_sbox
	./gen_sbox $(TE_INC) $(TD_INC) < /dev/null

# No external OpenSSL headers needed; use only our assembly and test

test_aes: $(ASM) test_aes.c $(TE_INC) $(TD_INC)
	$(CC) $(CFLAGS) $(ASM) test_aes.c -o $@

run: test_aes
	./test_aes

prof: test_aes
	./test_aes prof

# Simple perf stat over the profiler to observe core metrics
PERF_EVENTS ?= cycles,instructions,branches,branch-misses,cache-misses,L1-dcache-load-misses,icache.misses
perf: test_aes
	perf stat -e $(PERF_EVENTS) ./test_aes prof 20000 16 || true

clean:
	rm -f test_aes gen_sbox $(TE_INC) $(TD_INC)
