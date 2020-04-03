CC=clang
LLVM_CFLAGS=$(shell llvm-config-10 --cflags)
LLVM_LDFLAGS=$(shell llvm-config-10 --ldflags)
CFLAGS=-Wall -g

all: compiler bindgen

compiler: $(wildcard src/*.c)
	$(CC) $(LLVM_LDFLAGS) $(CFLAGS) $(LLVM_CFLAGS) -lLLVM-10 -o $@ src/main.c

bindgen: $(wildcard src/*.c) $(wildcard src/bindgen/*.c)
	$(CC) $(CFLAGS) $(LLVM_CFLAGS) -lclang -o $@ src/bindgen/main.c

.PHONY: clean test examples

clean:
	rm compiler
	rm bindgen

test: compiler
	@bash ./tests/run_tests.sh

examples: compiler bindgen
	./bindgen examples/stb_image.h > examples/stb_image.lang
	./compiler run examples/stb_image.lang
	./bindgen examples/glfw3.h > examples/glfw3.lang
	./compiler run examples/glfw3.lang
