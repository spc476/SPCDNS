#! /usr/bin/env lua
-- *************************************************************************
--
-- Copyright 2010 by Sean Conner.  All Rights Reserved.
--
-- This library is free software; you can redistribute it and/or modify it
-- under the terms of the GNU Lesser General Public License as published by
-- the Free Software Foundation; either version 3 of the License, or (at your
-- option) any later version.
--
-- This library is distributed in the hope that it will be useful, but
-- WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
-- or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
-- License for more details.
--
-- You should have received a copy of the GNU Lesser General Public License
-- along with this library; if not, see <http://www.gnu.org/licenses/>.
--
-- **************************************************************************

local dns  = require "org.conman.dns"

local e = dns.encode {
        id       = 1234,
        query    = true,
        rd       = true,
        opcode   = 'query',
        question = {
                name  = 'yahoo.com.',
                type  = 'mx',
                class = 'in'
        }
}

local r,err = dns.query('127.0.0.1',e)

if r == nil then
  print("error:",err)
  os.exit(1)
end

local d = dns.decode(r)

for i = 1 , #d.answers do
  print(string.format("%s %d %s %s %d %s",
                        d.answers[i].name,
                        d.answers[i].ttl,
                        d.answers[i].class,
                        d.answers[i].type,
                        d.answers[i].preference,
                        d.answers[i].exchange
                ))
end

