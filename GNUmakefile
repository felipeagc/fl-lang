LLVM_CFLAGS=$(shell llvm-config --cflags)
LLVM_LDFLAGS=$(shell llvm-config --ldflags)
CFLAGS=-Wall -g

CC=clang

CORE_FILES=$(wildcard core/*.lang)

all: compiler bindgen examples

compiler: $(wildcard src/*.c) $(wildcard src/*.h)
	$(CC) $(CFLAGS) $(LLVM_CFLAGS) $(LLVM_LDFLAGS) -lLLVM -o $@ src/main.c

bindgen: $(wildcard src/*.c) $(wildcard src/*.h) $(wildcard src/bindgen/*.c)
	$(CC) $(CFLAGS) $(LLVM_CFLAGS) -Wno-unused-function -lclang -o $@ src/bindgen/main.c

.PHONY: clean test examples game

clean:
	rm compiler
	rm bindgen
	rm examples/ray
	rm examples/table

test: compiler
	./compiler -r ./tests/run_tests.lang

examples:
	rm -f examples/ray examples/table
	./compiler build examples

game:
	rm -f examples/game
	./compiler build game

bindgen-tests: compiler bindgen
	./bindgen examples/stb_image.h > examples/stb_image.lang
	./compiler -r examples/stb_image.lang
	./bindgen examples/glfw3.h > examples/glfw3.lang
	./compiler -r examples/glfw3.lang

