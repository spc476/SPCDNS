#!/usr/bin/env lua
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
-- luacheck: ignore 611

local SERVER = "127.0.0.1"
local dns    = require "org.conman.dns"

-- **************************************************************

local function query(host,type)
  local e = dns.encode {
                id       = math.random(65535),
                query    = true,
                rd       = true,
                opcode   = 'query',
                question = {
                        name  = host,
                        type  = type,
                        class = 'in'
                }
        }
        
  local r,err = dns.query(SERVER,e)
  
  if r == nil then
    print("error:",err)
    return nil
  end
  
  return dns.decode(r)
end

-- ****************************************************************

local function query_a(host)
  local a,err = query(host,'a')
  
  if a == nil then
    print("error:",err)
    return nil
  end
  
  return a.answers[1]
end

-- ****************************************************************

local function query_mx(host)
  local mx,err = query(host,'mx')
  
  if mx == nil then
    print("error:",err)
    return nil
  end
  
  table.sort(mx.answers,function(a,b) return a.preference < b.preference end)
  
  for i = 1 , #mx.answers do
    mx.answers[i].ADDRESS = mx.additional[mx.answers[i].exchange]
    if mx.answers[i].ADDRESS == nil then
      mx.answers[i].ADDRESS = query_a(mx.answers[i].exchange)
    end
  end
  
  return mx.answers
end

-- **************************************************************

if #arg == 0 then
  io.stderr:write(string.format("usage: %s domain\n",arg[0]))
  os.exit(1)
end

local results = query_mx(arg[1])

for i = 1 , #results do
  local mx,ip
  
  mx = results[i].exchange
  ip = results[i].ADDRESS.address or "(none)"
  
  print(mx,ip)
end
