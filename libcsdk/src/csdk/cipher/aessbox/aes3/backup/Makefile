CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -std=c11

ASM  = aes-x86_64.s cpuid.s

all: test_aes

# No external OpenSSL headers needed; use only our assembly and test

test_aes: $(ASM) test_aes.c
	$(CC) $(CFLAGS) $(ASM) test_aes.c -o $@

run: test_aes
	./test_aes

clean:
	rm -f test_aes
