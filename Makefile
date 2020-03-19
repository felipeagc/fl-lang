CC=clang
CFLAGS=-Wall -g

compiler: compiler.c
	$(CC) $(CFLAGS) -o $@ $<

.PHONY: clean test

clean:
	rm compiler

test: compiler
	@bash ./tests/run_tests.sh
