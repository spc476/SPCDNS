
CC = cc -g -std=c99
#CFLAGS = -Wall -Wextra -pedantic
CFLAGS = -Os -fomit-frame-pointer -DNDEBUG
LFLAGS = -lcgi6

built/dotest : built/test.o built/codec.o built/mappings.o
	$(CC) -o $@ built/test.o built/codec.o built/mappings.o $(LFLAGS)
	
built/test.o : src/test.c src/dns.h src/mappings.h
	$(CC) $(CFLAGS) -c -o $@ $<

built/codec.o : src/codec.c src/dns.h
	$(CC) $(CFLAGS) -c -o $@ $<

built/mappings.o : src/mappings.c
	$(CC) $(CFLAGS) -c -o $@ $<
	
clean:
	/bin/rm -rf built/*
	/bin/rm -rf *~ src/*~
