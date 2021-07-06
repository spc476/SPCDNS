package = "org.conman.dns"
version = "2.0.0-1"

source = 
{
  url = "git://github.com/spc476/SPCDNS.git",
  tag = "v2.0.0"
}

description =
{
  homepage = "http://www.conman.org/software/spcdns/",
  maintainer = "Sean Conner <sean@conman.org>",
  license    = "LGPL",
  summary    = "A Lua module to encode DNS queries and decode DNS answers.",
  detailed   = [[
	A simple interface to encode and decode DNS queries.  This supports
	most of the commonly used DNS records and is meant to be a low level
	API upon which a generalized DNS query system can be built.
  ]]
}

dependencies = 
{
  "lua >= 5.1, <= 5.4"
}

build = 
{
  type           = "make",
  build_target   = "src/dns.so",
  install_target = "install-lua",
  
  platforms =
  {
    linux   = { build_variables = { CC = "gcc -std=c99" } },
    solaris = { build_varaibles = { CC = "c99"          } },
  },
  
  build_variables =
  {
    CC      = "$(CC)",
    CFLAGS  = "$(CFLAGS) -I$(LUA_INCDIR)",
    LDSHARE = "$(LIBFLAG)",
    LUA     = "$(LUA)",
  },
  
  install_variables =
  {
    LIBDIR = "$(LIBDIR)",
    LUA    = "$(LUA)",
  }
}
