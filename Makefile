CC=cl
LLVM_PATH=C:\llvm
CFLAGS=/nologo /I$(LLVM_PATH)\include /DEBUG /Zi

all: flc.exe

LLVM-C.dll:
	copy $(LLVM_PATH)\bin\LLVM-C.dll .

flc.exe: LLVM-C.dll src/*.c src/*.h
	$(CC) $(CFLAGS) -Feflc src/main.c src/microsoft_craziness.cpp $(LLVM_PATH)/lib/LLVM-C.lib
	del *.obj

test: .phony flc.exe
	.\flc.exe -r tests/run_tests.lang

examples: .phony flc.exe
	.\flc.exe build examples

clean:
	del examples\*.exe
	del *.exe
	del *.pdb
	del *.ilk
	del *.dll

.phony:
