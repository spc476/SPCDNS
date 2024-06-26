package = "org.conman.dns"
version = "2.1.3-1"
source = {
   url = "git+https://github.com/spc476/SPCDNS.git",
   tag = "v2.1.3"
}
description = {
   summary = "A Lua module to encode DNS queries and decode DNS answers.",
   detailed = [[
	A simple interface to encode and decode DNS queries.  This supports
	most of the commonly used DNS records and is meant to be a low level
	API upon which a generalized DNS query system can be built.
  ]],
   homepage = "http://www.conman.org/software/spcdns/",
   license = "LGPL",
   maintainer = "Sean Conner <sean@conman.org>"
}
dependencies = {
   "lua >= 5.1, <= 5.4"
}
build = {
   type = "make",
   platforms = {
      linux = {
         build_variables = {
            CC = "gcc -std=c99"
         }
      },
      solaris = {
         build_varaibles = {
            CC = "c99"
         }
      }
   },
   build_target = "src/dns.so",
   build_variables = {
      CC = "$(CC)",
      CFLAGS = "$(CFLAGS) -I$(LUA_INCDIR)",
      LDSHARE = "$(LIBFLAG)",
      LUA = "$(LUA)"
   },
   install_target = "install-lua",
   install_variables = {
      LIBDIR = "$(LIBDIR)",
      LUA = "$(LUA)"
   }
}
