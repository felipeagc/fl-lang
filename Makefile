CC=cl
LLVM_PATH=C:\llvm
CFLAGS=/nologo /I$(LLVM_PATH)\include /DEBUG /Zi

all: compiler.exe

LLVM-C.dll:
	copy $(LLVM_PATH)\bin\LLVM-C.dll .

compiler.exe: LLVM-C.dll src/*.c src/*.h
	$(CC) $(CFLAGS) -Fecompiler src/main.c src/microsoft_craziness.cpp $(LLVM_PATH)/lib/LLVM-C.lib
	del *.obj

test: .phony compiler.exe
	.\compiler.exe -r tests/run_tests.lang

examples: .phony compiler.exe
	.\compiler.exe build examples

clean:
	del examples\*.exe
	del *.exe
	del *.pdb
	del *.ilk
	del *.dll

.phony:
