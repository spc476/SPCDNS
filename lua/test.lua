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
  local e
  local r
  local err
  
  e,err  = dns.encode {
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
        
  if e == nil then
    return e,err
  end
  
  r,err = dns.query(SERVER,e)
  
  if r == nil then
    return r,err
  end
  
  return dns.decode(r)
end

-- ****************************************************************

local function print_txt(rec)
  if type(rec.txt) == 'string' then
    return rec.txt
  elseif type(rec.txt) == 'table' then
    local s = "("
    for i = 1 , #rec.txt do
      s = s .. string.format("\n\t\t\t%q",rec.txt[i])
    end
    s = s .. "\n\t\t)"
    return s
  else
    return ""
  end
end

local callbacks =
{
  NS    = function(rec) return rec.nsdname end,
  A     = function(rec) return rec.address end,
  AAAA  = function(rec) return rec.address end,
  CNAME = function(rec) return rec.cname end,
  MX    = function(rec) return string.format("%5d %s",rec.preference,rec.exchange) end,
  PTR   = function(rec) return rec.ptr end,
  HINFO = function(rec) return string.format("%q %q",rec.cpu,rec.os) end,
  SPF   = print_txt,
  TXT   = print_txt,
  SOA   = function(rec) return string.format([[
%s %s (
                %10d   ; Serial
                %10d   ; Refresh
                %10d   ; Retry
                %10d   ; Expire
                %10d ) ; Miminum
]],
                rec.mname,
                rec.rname,
                rec.serial,
                rec.refresh,
                rec.retry,
                rec.expire,
                rec.minimum ) end,
  NAPTR = function(rec) return string.format([[
%5d %5d (
                %q
                %q
                %q
                %s )
]],
                rec.order,
                rec.preference,
                rec.flags,
                rec.services,
                rec.regexp,
                rec.replacement) end,
  SRV = function(rec) return string.format(
                        "%5d %5d %5d %s",
                        rec.priority,
                        rec.weight,
                        rec.port,
                        rec.target) end,
  LOC = function(rec) return string.format([[
(
                %3d %2d %2d %s ; Latitude
                %3d %2d %2d %s ; Longitude
                %11d ; Altitude
                %11d ; Size
                %11d ; Horizontal Precision
                %11d ; Vertical Precision
                )
]],
                rec.latitude.deg,
                rec.latitude.min,
                rec.latitude.sec,
                rec.latitude.hemisphere,
                rec.longitude.deg,
                rec.longitude.min,
                rec.longitude.sec,
                rec.longitude.hemisphere,
                rec.altitude,
                rec.size,
                rec.horiz_pre,
                rec.vert_pre ) end
}

local function print_answers(tag,recs)
  io.stdout:write(string.format("\n;;; %s\n\n",tag))
  
  for i = 1 , #recs do
    local s = string.format("%-16s\t%d\t%s\t%s\t",
                recs[i].name,
                recs[i].ttl,
                recs[i].class,
                recs[i].type
        )
    s = s .. callbacks[recs[i].type](recs[i]) .. "\n"
    io.stdout:write(s)
  end
end

-- **********************************************************************


if #arg == 0 then
  io.stderr:write(string.format("usage: %s type domain\n",arg[0]))
  os.exit(1)
end

local results,err

results,err = query(arg[2],arg[1])

if results == nil then
  io.stderr:write(string.format(
        "error: query(%s,%s) = %s",
        arg[2],
        arg[1],
        err
        ))
  os.exit(1)
end

io.stdout:write(string.format([[
; Questions            = 1
; Answers              = %d
; Name Servers         = %d
; Additional Records   = %d
; Authoritative Result = %s
; Truncated Result     = %s
; Recursion Desired    = %s
; Recursion Available  = %s
; Result               = %s

;;; QUESTIONS

; %s %s %s
]],
        #results.answers,
        #results.nameservers,
        #results.additional,
        tostring(results.aa),
        tostring(results.tc),
        tostring(results.rd),
        tostring(results.ra),
        dns.strerror(results.rcode),
        results.question.name,
        results.question.class,
        results.question.type
))

print_answers("ANSWERS"     , results.answers)
print_answers("NAMESERVERS" , results.nameservers)
print_answers("ADDITIONAL"  , results.additional)

os.exit(0)
