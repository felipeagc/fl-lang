CC=clang

compiler: compiler.c
	$(CC) -o $@ $<

.PHONY: clean test

clean:
	rm compiler

test: compiler
	./compiler test.lang
