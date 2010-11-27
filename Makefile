
CC = gcc -g -std=c99
CFLAGS = -Wall -Wextra -pedantic
#CFLAGS = -Os -fomit-frame-pointer -DNDEBUG
LFLAGS = -lcgi6

all : built/dotest built/dns.so

built/dotest : built/test.o built/codec.o built/mappings.o
	$(CC) -o $@ built/test.o built/codec.o built/mappings.o $(LFLAGS)
	
built/test.o : src/test.c src/dns.h src/mappings.h
	$(CC) $(CFLAGS) -c -o $@ $<

built/codec.o : src/codec.c src/dns.h
	$(CC) $(CFLAGS) -c -o $@ $<

built/mappings.o : src/mappings.c
	$(CC) $(CFLAGS) -c -o $@ $<

built/dns.so : built/luadns.o built/codec.o built/mappings.o
	$(CC) -o $@ -shared -fpic 	\
		built/luadns.o		\
		built/codec.o		\
		built/mappings.o 	\
		$(LFLAGS)

built/luadns.o : src/luadns.c src/dns.h src/mappings.h
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	/bin/rm -rf built/*
	/bin/rm -rf *~ src/*~ lua/*~
