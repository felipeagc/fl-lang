CC=clang
LLVM_CFLAGS=$(shell llvm-config-10 --cflags)
LLVM_LDFLAGS=$(shell llvm-config-10 --ldflags)
CFLAGS=-Wall -g

all: compiler bindgen examples

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

examples/ray: compiler bindgen examples/ray.lang
	./compiler -o=$@ examples/ray.lang

examples: examples/ray

bindgen-tests: compiler bindgen
	./bindgen examples/stb_image.h > examples/stb_image.lang
	./compiler -r examples/stb_image.lang
	./bindgen examples/glfw3.h > examples/glfw3.lang
	./compiler -r examples/glfw3.lang


