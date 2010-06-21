CFLAGS := -Wall -fomit-frame-pointer -O9

VERSION := $(shell grep '\#define VERSION' netsed.c|sed 's/\#define VERSION "\(.*\)"/\1/')

all: netsed

clean:
	rm -f netsed core *.o netsed.tgz

check_version:
	@echo netsed $(VERSION)
	@grep $(VERSION) NEWS>/dev/null #version should apear in NEWS file
	@grep $(VERSION) README>/dev/null #same for README

release: clean check_version
	tar cfvz ../netsed-$(VERSION).tar.gz *

