CC=clang
LLVM_CFLAGS=$(shell llvm-config-10 --cflags)
LLVM_LDFLAGS=$(shell llvm-config-10 --ldflags)
CFLAGS=-Wall -g $(LLVM_CFLAGS)
LDFLAGS=$(LLVM_LDFLAGS) -lLLVM-10

compiler: compiler.c
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ $<

.PHONY: clean test

clean:
	rm compiler

test: compiler
	@bash ./tests/run_tests.sh
