LLVM_CFLAGS=$(shell llvm-config --cflags)
LLVM_LDFLAGS=$(shell llvm-config --ldflags)
CFLAGS=-Wall -g

CC=clang

CORE_FILES=$(wildcard core/*.lang)

.PHONY: clean test examples

all: flc flbindgen examples

flc: $(wildcard src/*.c) $(wildcard src/*.h)
	$(CC) $(CFLAGS) $(LLVM_CFLAGS) $(LLVM_LDFLAGS) -lLLVM -o $@ src/main.c

flbindgen: $(wildcard src/*.c) $(wildcard src/*.h) $(wildcard src/bindgen/*.c)
	$(CC) $(CFLAGS) $(LLVM_CFLAGS) -Wno-unused-function -lclang -o $@ src/bindgen/main.c

clean:
	rm flc
	rm flbindgen
	rm examples/ray
	rm examples/table

test: flc
	./flc -r ./tests/run_tests.lang

examples: flc flbindgen
	rm -f examples/ray examples/table
	./flc build examples

bindgen-tests: flc flbindgen
	./flbindgen examples/stb_image.h > examples/stb_image.lang
	./flc -r examples/stb_image.lang
	./flbindgen examples/glfw3.h > examples/glfw3.lang
	./flc -r examples/glfw3.lang

