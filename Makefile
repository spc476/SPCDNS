
#######################################################################
#
# Copyright 2010 by Sean Conner.  All Rights Reserved.
#
# This library is free software; you can redistribute it and/or modify it
# under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation; either version 3 of the License, or (at your
# option) any later version.
#
# This library is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
# License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this library; if not, see <http://www.gnu.org/licenses/>.
#
######################################################################

#================================================
# Linux
#================================================

CC     = gcc -std=c99
CFLAGS = -Wall -Wextra -pedantic -g
#CFLAGS = -Os -fomit-frame-pointer -DNDEBUG
PIC    = -fpic
LFLAGS = -lm 
LUA    = /usr/local/lib/lua/5.1
AR     = ar cr
RANLIB = ranlib

#=================================================
# Solaris
#=================================================

#CC     = cc -g -xc99
#CFLAGS =
#PIC    = -fpic
#LFLAGS = -lm -lnsl -lsocket
#LUA    = /usr/local/lib/lua/5.1
#AR     = ar cr
#RANLIB = ranlib

#=================================================

dotest : built/dotest 

lua : built/dns.so

lib : built/libspcdns.a built/libspcdnsmisc.a

so : built/libspcdns.so built/libspcdnsmisc.so

all : dotest lua lib so

#==================================================

built/libspcdns.a : built/codec.o built/mappings.o
	$(AR) $@ built/codec.o built/mappings.o
	$(RANLIB) $@

built/libspcdnsmisc.a : built/netsimple.o built/output.o
	$(AR) $@ $^
	$(RANLIB) $@

built/libspcdns.so : built/codec.pic.o built/mappings.pic.o built/output.pic.o
	$(CC) -shared -o $@ built/codec.pic.o built/mappings.pic.o built/output.pic.o

built/libspcdnsmisc.so : built/netsimple.pic.o built/output.pic.o
	$(CC) -shared -o $@ $^

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

built/output.o : src/output.c src/output.h
	$(CC) $(CFLAGS) -c -o $@ $<

built/output.pic.o : src/output.c src/output.h
	$(CC) $(CFLAGS) $(PIC) -c -o $@ $<

#==============================================================


built/dotest : built/test.o 		\
		built/codec.o 		\
		built/mappings.o	\
		built/netsimple.o	\
		built/output.o
	$(CC) -o $@ built/test.o 	\
		built/codec.o		\
		built/mappings.o	\
		built/netsimple.o	\
		built/output.o		\
		$(LFLAGS)

built/test.o : src/test.c src/dns.h src/mappings.h src/netsimple.h src/output.h
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

tarball:
	(cd .. ; tar czvf /tmp/spcdns.tar.gz -X spcdns/.exclude spcdns/ )
