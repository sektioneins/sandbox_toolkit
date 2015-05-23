GCC_BIN=`xcrun --sdk macosx --find gcc`
GCC=$(GCC_BASE) -arch x86_64
SDK=`xcrun --sdk macosx --show-sdk-path`

CFLAGS = 
GCC_BASE = $(GCC_BIN) -Os $(CFLAGS) -Wimplicit -isysroot $(SDK) 

all: extract_sbprofiles

extract_sbprofiles: extract_sbprofiles.c
	$(GCC) -o $@ $^

clean:
	rm -f *.o *.bin extract_sbprofiles