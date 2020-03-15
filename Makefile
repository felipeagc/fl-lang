CC=clang
CFLAGS=-Wall

compiler: compiler.c
	$(CC) $(CFLAGS) -o $@ $<

.PHONY: clean test

clean:
	rm compiler

test: compiler
	@find tests/ -type f -name "*.lang" -exec ./compiler {} \;
