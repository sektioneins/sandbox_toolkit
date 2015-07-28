GCC_BIN=`xcrun --sdk macosx --find gcc`
GCC=$(GCC_BASE) -arch x86_64
SDK=`xcrun --sdk macosx --show-sdk-path`

CFLAGS = 
GCC_BASE = $(GCC_BIN) -Os $(CFLAGS) -Wimplicit -isysroot $(SDK) -lsandbox

all: compile_sb

compile_sb: compile_sb.c
	$(GCC) -o $@ $^

clean:
	rm -f *.o compile_sb