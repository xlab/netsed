CFLAGS = -Wall -fomit-frame-pointer -O9

all: netsed

clean:
	rm -f netsed core *.o netsed.tgz

tgz: clean
	tar cfvz netsed.tgz *

publish: tgz
	scp netsed.tgz lcamtuf@dione:public_html/