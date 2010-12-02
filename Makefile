
CC = gcc -g -std=c99
CFLAGS = -Wall -Wextra -pedantic
#CFLAGS = -Os -fomit-frame-pointer -DNDEBUG
PIC=-fpic
LFLAGS = -lm -lcgi6
LUA = /usr/local/lib/lua/5.1
AR = ar cr
RANLIB = ranlib


all : built/dotest built/dns.so built/libspcdns.a built/libspcdns.so

built/libspcdns.a : built/codec.o built/mappings.o
	$(AR) $@ built/codec.o built/mappings.o
	$(RANLIB) $@

built/libspcdns.so : built/codec.pic.o built/mappings.pic.o
	$(CC) -shared -o $@ built/codec.pic.o built/mappings.pic.o 
	
built/codec.o : src/codec.c src/dns.h
	$(CC) $(CFLAGS) -c -o $@ $<

built/codec.pic.o : src/codec.c src/dns.h
	$(CC) $(CFLAGS) $(PIC) -c -o $@ $<
	
built/mappings.o : src/mappings.c src/mappings.h
	$(CC) $(CFLAGS) -c -o $@ $<

built/mappings.pic.o : src/mappings.c src/mappings.h
	$(CC) $(CFLAGS) $(PIC) -c -o $@ $<

built/netsimple.o : src/netsimple.c src/netsimple.h
	$(CC) $(CFLAGS) -c -o $@ $<

built/netsimple.pic.o : src/netsimple.c src/netsimple.h
	$(CC) $(CFLAGS) $(PIC) -c -o $@ $<

#==============================================================


built/dotest : built/test.o 		\
		built/codec.o 		\
		built/mappings.o	\
		built/netsimple.o
	$(CC) -o $@ built/test.o 	\
		built/codec.o		\
		built/mappings.o	\
		built/netsimple.o	\
		$(LFLAGS)

built/test.o : src/test.c src/dns.h src/mappings.h src/netsimple.h
	$(CC) $(CFLAGS) -c -o $@ $<

#=============================================================

built/dns.so : built/luadns.o 		\
		built/codec.pic.o 	\
		built/mappings.pic.o	\
		built/netsimple.pic.o
	$(CC) -o $@ -shared 	 	\
		built/luadns.o		\
		built/codec.pic.o	\
		built/mappings.pic.o 	\
		built/netsimple.pic.o

	
built/luadns.o : src/luadns.c src/dns.h src/mappings.h
	$(CC) $(CFLAGS) $(PIC) -c -o $@ $<

#===========================================================

install-lua: built/dns.so
	install -d $(LUA)/org/conman
	install built/dns.so $(LUA)/org/conman
	
clean:
	/bin/rm -rf built/*
	/bin/rm -rf *~ src/*~ lua/*~
