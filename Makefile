CC=cl
LLVM_PATH=C:\llvm
CFLAGS=/nologo /I$(LLVM_PATH)\include

all: compiler.exe

LLVM-C.dll:
	copy $(LLVM_PATH)\bin\LLVM-C.dll .

compiler.exe: LLVM-C.dll src/*.c
	$(CC) $(CFLAGS) -Fecompiler src/main.c src/microsoft_craziness.cpp $(LLVM_PATH)/lib/LLVM-C.lib advapi32.lib ole32.lib oleaut32.lib
	del *.obj

clean:
	del compiler.exe
	del LLVM-C.dll
