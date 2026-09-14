CC ?= clang
PKG_CONFIG ?= pkg-config
CFLAGS ?= -O2 -std=c11 -Wall -Wextra -Wpedantic
CPPFLAGS += -Iinclude $(shell $(PKG_CONFIG) --cflags openssl zlib)
LDLIBS += $(shell $(PKG_CONFIG) --libs openssl zlib)
SRC := $(wildcard src/*.c)
OBJ := $(SRC:.c=.o)

.PHONY: all clean release install test

all: frogurl

frogurl: $(OBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(OBJ) $(LDLIBS)

src/%.o: src/%.c include/frogurl.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

release:
	$(MAKE) clean
	$(MAKE) CC=clang CFLAGS='-Oz -flto -std=c11 -DNDEBUG -ffunction-sections -fdata-sections -fno-unwind-tables -fno-asynchronous-unwind-tables' LDFLAGS='-fuse-ld=lld -flto -Wl,--gc-sections -Wl,-O2'
	@if command -v llvm-strip >/dev/null 2>&1; then llvm-strip -s frogurl; else strip -s frogurl; fi

test: frogurl
	python3 tests/run_tests.py ./frogurl

install: frogurl
	install -Dm755 frogurl $(DESTDIR)/usr/local/bin/frogurl

clean:
	rm -f $(OBJ) frogurl
