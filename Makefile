ARCH ?= arm64e
IOSMIN ?= 16.0

# Under GitHub Actions the macOS runner provides a real iOS SDK via `xcrun`.
ifneq ($(SDKPATH),)
  SYSROOT := -isysroot $(SDKPATH)
else
  SYSROOT := $(shell xcrun --sdk iphoneos --show-sdk-path 2>/dev/null | sed 's/^/-isysroot /')
endif

CC      ?= xcrun --sdk iphoneos clang
CFLAGS  := -target aarch64-apple-ios$(IOSMIN)$(ARCH) $(SYSROOT) \
           -std=gnu11 -Os -fPIC -Wall -Wno-unused-function
LDFLAGS := -dynamiclib -install_name @rpath/CyanideZH.dylib -lobjc -Wl,-x

OBJS := main.o table.o

all: CyanideZH.dylib

main.o: src/main.m src/cz_table.h
	$(CC) $(CFLAGS) -c src/main.m -o $@

table.o: src/table.c src/cz_table.h
	$(CC) $(CFLAGS) -c src/table.c -o $@

CyanideZH.dylib: $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS)
	ldid -S $@ || codesign --force --sign - $@ || true

clean:
	rm -f $(OBJS) CyanideZH.dylib

.PHONY: all clean
