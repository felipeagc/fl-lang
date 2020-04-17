LLVM_CFLAGS=$(shell llvm-config --cflags)
LLVM_LDFLAGS=$(shell llvm-config --ldflags)
CFLAGS=-Wall -g

CC=clang

CORE_FILES=$(wildcard core/*.lang)

all: compiler bindgen examples

compiler: $(wildcard src/*.c)
	$(CC) $(LLVM_LDFLAGS) $(CFLAGS) $(LLVM_CFLAGS) -lLLVM -o $@ src/main.c

bindgen: $(wildcard src/*.c) $(wildcard src/bindgen/*.c)
	$(CC) $(CFLAGS) $(LLVM_CFLAGS) -L/usr/local/opt/llvm/lib -Wno-unused-function -lclang -o $@ src/bindgen/main.c

.PHONY: clean test examples

clean:
	rm compiler
	rm bindgen
	rm examples/ray
	rm examples/table

test: compiler
	@bash ./tests/run_tests.sh

examples/ray: compiler bindgen examples/ray.lang $(CORE_FILES)
	./compiler -o=$@ examples/ray.lang

examples/table: compiler bindgen examples/table.lang $(CORE_FILES)
	./compiler -o=$@ examples/table.lang

examples/sdl_game: compiler bindgen examples/sdl.lang examples/sdl_game.lang $(CORE_FILES)
	./compiler -o=$@ -l=SDL2 examples/sdl_game.lang

examples: examples/ray examples/table examples/sdl_game

bindgen-tests: compiler bindgen
	./bindgen examples/stb_image.h > examples/stb_image.lang
	./compiler -r examples/stb_image.lang
	./bindgen examples/glfw3.h > examples/glfw3.lang
	./compiler -r examples/glfw3.lang


