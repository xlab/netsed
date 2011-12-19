CFLAGS += -Wall -fomit-frame-pointer
PREFIX ?= /usr/local

ifeq "$(shell uname -s)" "SunOS"
	LDFLAGS += -lsocket
endif

VERSION := $(shell grep '\#define VERSION' netsed.c|sed 's/\#define VERSION "\(.*\)"/\1/')

all: netsed

install: netsed
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 0755 netsed $(DESTDIR)$(PREFIX)/bin/

clean:
	rm -f netsed core *.o netsed.tgz

doc:
	doxygen doxygen.conf

check_version:
	@echo netsed $(VERSION)
	@grep "netsed $(VERSION)" NEWS>/dev/null ||(echo "version should appear in NEWS file"; exit 1)
	@grep "netsed $(VERSION)" README>/dev/null ||(echo "version should appear in README file"; exit 1)

.PHONY: test

test: netsed
	ruby test/ts_full.rb

test/doc:
	cd test;LANG=C rdoc -a --inline-source -d *.rb

release_tag: check_version
	@if (git status --porcelain | grep '^ M') then echo "you have modified files, cannot tag"; exit 2; else exit 0; fi
	git tag $(VERSION)

quick_archive: clean check_version
	tar cfvz ../netsed-$(VERSION).tar.gz *

release_archive:
	@git show-ref --tags $(VERSION) > /dev/null ||(echo "to release first create a tag with the current version $(VERSION)"; exit 3)
	fakeroot git archive --format=tar --prefix=netsed-$(VERSION)/ $(VERSION) | gzip > ../netsed-$(VERSION).tar.gz

release: release_archive
	@echo "netsed-$(VERSION) release" > ../netsed-$(VERSION).txt
	@echo -n "commit " >> ../netsed-$(VERSION).txt
	@git rev-parse --verify $(VERSION) >> ../netsed-$(VERSION).txt
	@cd .. && md5sum netsed-$(VERSION).tar.gz >> netsed-$(VERSION).txt
	@cd .. && sha1sum netsed-$(VERSION).tar.gz >> netsed-$(VERSION).txt
	@cd .. && sha256sum netsed-$(VERSION).tar.gz >> netsed-$(VERSION).txt
	@cd .. && gpg -o netsed-$(VERSION).sig --clearsign netsed-$(VERSION).txt

# and upload netsed-$(VERSION).tar.gz netsed-$(VERSION).sig
