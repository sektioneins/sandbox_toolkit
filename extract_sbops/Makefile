GCC_BIN=`xcrun --sdk macosx --find gcc`
GCC=$(GCC_BASE) -arch x86_64
SDK=`xcrun --sdk macosx --show-sdk-path`

CFLAGS = 
GCC_BASE = $(GCC_BIN) -Os $(CFLAGS) -Wimplicit -isysroot $(SDK) 

all: extract_sbops

extract_sbops: extract_sbops.c
	$(GCC) -o $@ $^

clean:
	rm -f *.o extract_sbops