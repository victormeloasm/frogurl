ifeq ($(origin CC),default)
CC := $(shell command -v clang 2>/dev/null || command -v cc)
endif
PKG_CONFIG ?= pkg-config
CFLAGS ?= -O2 -std=c11 -Wall -Wextra -Wpedantic
CPPFLAGS += -Iinclude
ifneq ($(shell command -v $(PKG_CONFIG) 2>/dev/null),)
CPPFLAGS += $(shell $(PKG_CONFIG) --cflags openssl zlib)
LDLIBS += $(shell $(PKG_CONFIG) --libs openssl zlib)
else
LDLIBS += -lssl -lcrypto -lz
endif
HARDEN_CFLAGS ?= -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE
HARDEN_LDFLAGS ?= -pie -Wl,-z,relro,-z,now,-z,noexecstack
SRC := $(wildcard src/*.c)
OBJ := $(SRC:.c=.o)

.PHONY: all clean release install test test-security sanitize fuzz-smoke

all: frogurl

frogurl: $(OBJ)
	$(CC) $(CFLAGS) $(HARDEN_CFLAGS) $(LDFLAGS) $(HARDEN_LDFLAGS) -o $@ $(OBJ) $(LDLIBS)

src/%.o: src/%.c include/frogurl.h
	$(CC) $(CPPFLAGS) $(CFLAGS) $(HARDEN_CFLAGS) -c -o $@ $<

release:
	$(MAKE) clean
	$(MAKE) CFLAGS='-Os -flto -std=c11 -Wall -Wextra -Wpedantic -DNDEBUG -ffunction-sections -fdata-sections -fno-unwind-tables -fno-asynchronous-unwind-tables' LDFLAGS='-flto -Wl,--gc-sections -Wl,-O2'
	@if command -v llvm-strip >/dev/null 2>&1; then llvm-strip -s frogurl; else strip -s frogurl; fi

test: frogurl
	python3 tests/run_tests.py ./frogurl
	python3 tests/test_protocols.py ./frogurl

test-security: test

tests/fuzz_parsers: tests/fuzz_parsers.c src/url.c src/util.c src/net.c include/frogurl.h
	$(CC) $(CPPFLAGS) $(CFLAGS) $(HARDEN_CFLAGS) -UNDEBUG $(LDFLAGS) $(HARDEN_LDFLAGS) -o $@ tests/fuzz_parsers.c src/url.c src/util.c src/net.c $(LDLIBS)

fuzz-smoke: tests/fuzz_parsers
	./tests/fuzz_parsers

sanitize:
	$(MAKE) clean
	$(MAKE) CFLAGS='-O1 -g -std=c11 -Wall -Wextra -Wpedantic -fsanitize=address,undefined -fno-omit-frame-pointer' LDFLAGS='-fsanitize=address,undefined' test fuzz-smoke

install: frogurl
	install -Dm755 frogurl $(DESTDIR)/usr/local/bin/frogurl

clean:
	rm -f $(OBJ) frogurl tests/fuzz_parsers
