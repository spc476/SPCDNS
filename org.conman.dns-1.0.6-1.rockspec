package = "org.conman.dns"
version = "1.0.6-1"

source = 
{
  url = "git://github.com/spc476/SPCDNS.git",
  tag = "v1.0.6"
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
  "lua ~> 5.1"
}

build = 
{
  type           = "make",
  build_target   = "lua",
  install_target = "install-lua",

  build_variables =
  {
    CC     = "$(CC) -std=c99",
    CFLAGS = "$(CFLAGS)",
  },

  install_variables =
  {
    LUA = "$(LIBDIR)"
  }
}
