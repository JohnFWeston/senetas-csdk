CC ?= gcc
# Optimize for modern Intel; users can still override CFLAGS externally
# CFLAGS ?= -O3 -Wall -Wextra -std=c11 -fomit-frame-pointer -fno-asynchronous-unwind-tables -march=native -mtune=native -falign-functions=32 -falign-loops=32

TE_INC = Te_words.inc
TD_INC = Td_words.inc

all: gen_sbox $(TE_INC) $(TD_INC)

# Generate S-box include files (default S-box unless stdin provided)
gen_sbox: gen_sbox.c
	$(CC) $(CFLAGS) $< -o $@

$(TE_INC) $(TD_INC): gen_sbox
	./gen_sbox $(TE_INC) $(TD_INC) < /dev/null

clean:
	rm -f gen_sbox $(TE_INC) $(TD_INC)
