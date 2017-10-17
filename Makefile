
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

VERSION := $(shell git describe --tag)

CC      = gcc -std=c99
CFLAGS  = -Wall -Wextra -pedantic -g
LDFLAGS =
LDLIBS  = -lm
CSHARE  = -fPIC
LDSHARE = -shared

#=================================================

INSTALL         = /usr/bin/install
INSTALL_PROGRAM = $(INSTALL)
INSTALL_DATA    = $(INSTALL) -m 644

prefix = /usr/local
libdir = $(prefix)/lib

LUA         ?= lua
LUA_VERSION := $(shell $(LUA) -e "print(_VERSION:match '^Lua (.*)')")
LIBDIR      ?= $(libdir)/lua/$(LUA_VERSION)

ifneq ($(LUA_INCDIR),)
  override CFLAGS += -I$(LUA_INCDIR)
endif

#=================================================

%.a :
	$(AR) $(ARFLAGS) $@ $?

%.oo : %.c
	$(CC) $(CFLAGS) $(CSHARED) -c -o $@ $<

%.so :
	$(CC) $(LDSHARE) -o $@ $^

#=================================================

.PHONY: all install-lua uninstall-lua clean dist depend
all   : src/dotest src/libspcdns.a src/dns.so

src/dotest      : src/dotest.o src/libspcdns.a
src/libspcdns.a : src/codec.o src/mappings.o src/netsimple.o src/output.o
src/dns.so      : src/luadns.oo src/codec.oo src/mappings.oo src/netsimple.oo

install-lua : src/dns.so
	$(INSTALL) -d $(DESTDIR)$(LIBDIR)/org/conman
	$(INSTALL_PROGRAM) src/dns.so $(DESTDIR)$(LIBDIR)/org/conman

uninstall-lua :
	$(RM) $(DESTDIR)$(LIBDIR)/org/conman/dns.so

clean:
	$(RM) $(shell find . -name '*.o')
	$(RM) $(shell find . -name '*.so')
	$(RM) $(shell find . -name '*.oo')
	$(RM) $(shell find . -name '*.a')
	$(RM) $(shell find . -name '*~')
	$(RM) Makefile.bak src/dotest

dist:
	git archive -o /tmp/spcdns-$(VERSION).tar.gz --prefix spcdns/ $(VERSION)

depend:
	makedepend -Y -- $(CFLAGS) -- src/*.c 2>/dev/null

# DO NOT DELETE

src/codec.o: src/dns.h
src/dotest.o: src/dns.h src/mappings.h src/netsimple.h src/output.h
src/luadns.o: src/dns.h src/mappings.h src/netsimple.h
src/mappings.o: src/dns.h src/mappings.h
src/netsimple.o: src/dns.h src/netsimple.h
src/output.o: src/dns.h src/mappings.h src/output.h
