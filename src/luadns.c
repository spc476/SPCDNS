/*************************************************************************
*
* Copyright 2010 by Sean Conner.  All Rights Reserved.
*
* This library is free software; you can redistribute it and/or modify it
* under the terms of the GNU Lesser General Public License as published by
* the Free Software Foundation; either version 3 of the License, or (at your
* option) any later version.
*
* This library is distributed in the hope that it will be useful, but
* WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
* or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
* License for more details.
*
* You should have received a copy of the GNU Lesser General Public License
* along with this library; if not, see <http://www.gnu.org/licenses/>.
*
**************************************************************************/

/**********************************************************************
*
* Implements Lua bindings for my DNS library.  This exports four functions
* in the org.conman.dns object:
*
*       encode(t)
*
*               Accepts a table in the form:
*
*                       {
*                         id       = some_number,
*                         query    = true,      -- making a query
*                         rd       = true,      -- for recursive queries
*                         opcode   = 'query',
*                         question = {
*                                       name = 'www.example.com',
*                                       type = 'loc',
*                                       class = 'in'
*                               }, -- and optionally
*                         additional = {
*                               name = '.',
*                               type = 'opt',
*                               udp_payload = 1464,
*                               version     = 0,
*                               fdo         = false,
*                               opts        = {
*                                       {
*                                         type = 'nsid', -- or a number
*                                         data = "..."
*                                       } -- and more, if required
*                               }
*                         }
*                       }
*
*               And returns a binary string that is the wire format of the
*               query.  This binary string can then be sent over a UDP or
*               TCP packet to a DNS server.
*
*               This returns a binary string on success, nil,rcode on
*               failre.
*
*               See lua/test.lua for an example of using this function.
*
*       decode(bs)
*
*               Decodes a binary string into a table (similar to the table
*               above) for easy use of the DNS response.
*
*               This returns a table on success, or nil,rcode on failure.
*
*               See lua/test.lua for an example of using this function.
*
*       query(server,bs)
*
*               Sends the encoded binary string to the given server.  The
*               server variable is a string of the IP address (IPv4 or
*               IPv6)---hostnames will fail.
*
*               This function is very stupid simple; it sends the request,
*               and if it doesn't see a reply in 15 seconds, it returns a
*               failure.  No restransmission of the packet is done.  This is
*               probably fine for simple applications but not for anything
*               heavy duty or rubust.
*
*               This returns a binary string of the reponse, or nil,rcode on
*               failure.
*
*       strerror(rcode)
*
*               Returns a string representation of the server response, or
*               the return value from a failed query() call.  This function
*               does not fail (if it does, there's more to worry about).
*
*
* This code is written to C99.
*
***************************************************************************/

#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <errno.h>
#include <ctype.h>
#include <math.h>
#include <assert.h>

#include <arpa/inet.h>

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

#include "dns.h"
#include "mappings.h"
#include "netsimple.h"

/********************************************************************/

#if LUA_VERSION_NUM == 501
#  define lua_rawlen(L,i) lua_objlen((L),(i))
#endif

/********************************************************************/

#if LUA_VERSION_NUM == 501
static int lua_absindex(lua_State *L,int idx)
{
  return (idx > 0) || (idx < LUA_REGISTRYINDEX)
       ? idx
       : lua_gettop(L) + idx + 1
       ;
}
#endif

/********************************************************************/

static void to_question(lua_State *L,dns_question_t **pq,size_t *pqs,int idx)
{
  assert(L   != NULL);
  assert(pq  != NULL);
  assert(pqs != NULL);
  assert(idx != 0);
  
  /*----------------------------------------------------------------------
  ; while dns_encode() supports more than one question, most servers today
  ; (2021) *still* do not support more than one question, and most of the
  ; existing Lua code assumes one question.  So let's keep with tradition
  ; for now.
  ;-----------------------------------------------------------------------*/
  
  idx  = lua_absindex(L,idx);
  *pqs = 1;
  *pq  = lua_newuserdata(L,*pqs * sizeof(dns_question_t));
  
  lua_getfield(L,idx,"name");
  lua_getfield(L,idx,"type");
  lua_getfield(L,idx,"class");
  
  (*pq)[0].name  = luaL_checkstring(L,-3);
  (*pq)[0].type  = dns_type_value(luaL_optstring(L,-2,"A"));
  (*pq)[0].class = dns_class_value(luaL_optstring(L,-1,"IN"));
  lua_pop(L,3);
}

/********************************************************************/

static void to_dnsgpos_angle(lua_State *L,dnsgpos_angle *ang,int idx,bool lat)
{
  lua_Number sec;
  
  idx = lua_absindex(L,idx);
  lua_getfield(L,idx,"deg");
  lua_getfield(L,idx,"min");
  lua_getfield(L,idx,"sec");
  
  ang->deg  = luaL_checkinteger(L,-3);
  ang->min  = luaL_checkinteger(L,-2);
  ang->frac = modf(luaL_checknumber(L,-1),&sec) * 1000.0;
  ang->sec  = sec;
  lua_pop(L,3);
  
  lua_getfield(L,idx,"hemisphere");
  if (!lua_isnil(L,-1))
  {
    char const *s = luaL_checkstring(L,-1);
    if (lat)
      ang->nw = toupper(*s) == 'N';
    else
      ang->nw = toupper(*s) == 'W';
    lua_pop(L,1);
  }
  else
  {
    lua_getfield(L,idx,"nw");
    ang->nw = lua_toboolean(L,-1);
    lua_pop(L,2);
  }
}

/********************************************************************/

static void to_answers(lua_State *L,dns_answer_t **pa,size_t *pas,int idx)
{
  int top;
  int tidx;
  
  assert(L   != NULL);
  assert(pa  != NULL);
  assert(pas != NULL);
  assert(idx != 0);
  
  idx  = lua_absindex(L,idx);
  *pas = lua_rawlen(L,idx);
  *pa  = lua_newuserdata(L,*pas * sizeof(dns_answer_t));
  top  = lua_gettop(L);
  
  for (size_t i = 0 ; i < *pas ; i++)
  {
    lua_pushinteger(L,i + 1);
    lua_gettable(L,idx);
    tidx = lua_absindex(L,-1);
    
    lua_getfield(L,tidx,"name");
    lua_getfield(L,tidx,"type");
    lua_getfield(L,tidx,"class");
    lua_getfield(L,tidx,"ttl");
    
    (*pa)[i].generic.name  = luaL_checkstring(L,-4);
    (*pa)[i].generic.type  = dns_type_value(luaL_checkstring(L,-3));
    (*pa)[i].generic.class = dns_class_value(luaL_optstring(L,-2,"IN"));
    (*pa)[i].generic.ttl   = luaL_checkinteger(L,-1);
    
    switch((*pa)[i].generic.type)
    {
      case RR_A:
           lua_getfield(L,tidx,"raw_address");
           if (!lua_isnil(L,-1))
           {
             size_t      s;
             char const *a = luaL_checklstring(L,-1,&s);
             if (s != 4) luaL_error(L,"not an IP address in A record");
             memcpy(&(*pa)[i].a.address,a,4);
           }
           else
           {
             lua_getfield(L,tidx,"address");
             if (inet_pton(AF_INET,luaL_checkstring(L,-1),&(*pa)[i].a.address) != 0)
               luaL_error(L,"Not an IP address in A record");
           }
           break;
           
      case RR_SOA:
           lua_getfield(L,tidx,"mname");
           lua_getfield(L,tidx,"rname");
           lua_getfield(L,tidx,"serial");
           lua_getfield(L,tidx,"refresh");
           lua_getfield(L,tidx,"retry");
           lua_getfield(L,tidx,"expire");
           lua_getfield(L,tidx,"minimum");
           (*pa)[i].soa.mname   = luaL_checkstring(L,-7);
           (*pa)[i].soa.rname   = luaL_checkstring(L,-6);
           (*pa)[i].soa.serial  = luaL_checkinteger(L,-5);
           (*pa)[i].soa.refresh = luaL_checkinteger(L,-4);
           (*pa)[i].soa.retry   = luaL_checkinteger(L,-3);
           (*pa)[i].soa.expire  = luaL_checkinteger(L,-2);
           (*pa)[i].soa.minimum = luaL_checkinteger(L,-1);
           break;
           
      case RR_NAPTR:
           lua_getfield(L,tidx,"order");
           lua_getfield(L,tidx,"preference");
           lua_getfield(L,tidx,"flags");
           lua_getfield(L,tidx,"services");
           lua_getfield(L,tidx,"regexp");
           lua_getfield(L,tidx,"replacement");
           (*pa)[i].naptr.order       = luaL_checkinteger(L,-6);
           (*pa)[i].naptr.preference  = luaL_checkinteger(L,-5);
           (*pa)[i].naptr.flags       = luaL_checkstring(L,-4);
           (*pa)[i].naptr.services    = luaL_checkstring(L,-3);
           (*pa)[i].naptr.regexp      = luaL_checkstring(L,-2);
           (*pa)[i].naptr.replacement = luaL_checkstring(L,-1);
           break;
           
      case RR_AAAA:
           lua_getfield(L,tidx,"raw_address");
           if (!lua_isnil(L,-1))
           {
             size_t s;
             char const *a = luaL_checklstring(L,-1,&s);
             if (s != 16) luaL_error(L,"not an IPv6 address in AAAA record");
             memcpy(&(*pa)[i].aaaa.address,a,16);
           }
           else
           {
             lua_getfield(L,tidx,"address");
             if (inet_pton(AF_INET6,luaL_checkstring(L,-1),&(*pa)[i].aaaa.address) != 0)
               luaL_error(L,"not an IPv6 address in AAAA record");
           }
           break;
           
      case RR_SRV:
           lua_getfield(L,tidx,"priority");
           lua_getfield(L,tidx,"weight");
           lua_getfield(L,tidx,"port");
           lua_getfield(L,tidx,"target");
           (*pa)[i].srv.priority = luaL_checkinteger(L,-4);
           (*pa)[i].srv.weight   = luaL_checkinteger(L,-3);
           (*pa)[i].srv.port     = luaL_checkinteger(L,-2);
           (*pa)[i].srv.target   = luaL_checkstring(L,-1);
           break;
           
      case RR_WKS:
           lua_getfield(L,tidx,"raw_address");
           if (!lua_isnil(L,-1))
           {
             size_t      s;
             char const *a = luaL_checklstring(L,-1,&s);
             if (s != 4) luaL_error(L,"not an IP address in A record");
             memcpy(&(*pa)[i].wks.address,a,4);
           }
           else
           {
             lua_getfield(L,tidx,"address");
             if (inet_pton(AF_INET,luaL_checkstring(L,-1),&(*pa)[i].wks.address) != 0)
               luaL_error(L,"Not an IP address in A record");
           }
           
           lua_getfield(L,tidx,"protocol");
           lua_getfield(L,tidx,"bits");
           (*pa)[i].wks.protocol = luaL_checkinteger(L,-1);
           (*pa)[i].wks.bits     = (uint8_t *)luaL_checklstring(L,-2,&(*pa)[i].wks.numbits);
           break;
           
      case RR_GPOS:
           lua_getfield(L,tidx,"longitude");
           lua_getfield(L,tidx,"latitude");
           lua_getfield(L,tidx,"altitude");
           to_dnsgpos_angle(L,&(*pa)[i].gpos.longitude,-3,false);
           to_dnsgpos_angle(L,&(*pa)[i].gpos.latitude,-2,true);
           (*pa)[i].gpos.altitude = luaL_checknumber(L,-1);
           break;
           
      case RR_LOC:
           lua_getfield(L,tidx,"version");
           lua_getfield(L,tidx,"size");
           lua_getfield(L,tidx,"horiz_pre");
           lua_getfield(L,tidx,"vert_pre");
           lua_getfield(L,tidx,"latitude");
           lua_getfield(L,tidx,"longitude");
           lua_getfield(L,tidx,"altitude");
           (*pa)[i].loc.version   = luaL_optinteger(L,-7,0);
           (*pa)[i].loc.size      = luaL_checkinteger(L,-6);
           (*pa)[i].loc.horiz_pre = luaL_checkinteger(L,-5);
           (*pa)[i].loc.vert_pre  = luaL_checkinteger(L,-4);
           to_dnsgpos_angle(L,&(*pa)[i].loc.latitude,-3,true);
           to_dnsgpos_angle(L,&(*pa)[i].loc.longitude,-2,false);
           (*pa)[i].loc.altitude  = luaL_checkinteger(L,-1);
           break;
           
      case RR_PX:
           lua_getfield(L,tidx,"map822");
           lua_getfield(L,tidx,"mapx400");
           (*pa)[i].px.map822  = luaL_checkstring(L,-2);
           (*pa)[i].px.mapx400 = luaL_checkstring(L,-1);
           break;
           
      case RR_RP:
           lua_getfield(L,tidx,"mbox");
           lua_getfield(L,tidx,"domain");
           (*pa)[i].rp.mbox   = luaL_checkstring(L,-2);
           (*pa)[i].rp.domain = luaL_checkstring(L,-1);
           break;
           
      case RR_MINFO:
           lua_getfield(L,tidx,"rmailbx");
           lua_getfield(L,tidx,"emailbx");
           (*pa)[i].minfo.rmailbx = luaL_checkstring(L,-2);
           (*pa)[i].minfo.emailbx = luaL_checkstring(L,-1);
           break;
           
      case RR_AFSDB:
           lua_getfield(L,tidx,"subtype");
           lua_getfield(L,tidx,"hostname");
           (*pa)[i].afsdb.subtype  = luaL_checkinteger(L,-2);
           (*pa)[i].afsdb.hostname = luaL_checkstring(L,-1);
           break;
           
      case RR_RT:
           lua_getfield(L,tidx,"preference");
           lua_getfield(L,tidx,"host");
           (*pa)[i].rt.preference = luaL_checkinteger(L,-2);
           (*pa)[i].rt.host       = luaL_checkstring(L,-1);
           break;
           
      case RR_MX:
           lua_getfield(L,tidx,"preference");
           lua_getfield(L,tidx,"exchange");
           (*pa)[i].mx.preference = luaL_checkinteger(L,-2);
           (*pa)[i].mx.exchange   = luaL_checkstring(L,-1);
           break;
           
      case RR_NSAP:
           lua_getfield(L,tidx,"length");
           lua_getfield(L,tidx,"address");
           (*pa)[i].nsap.length      = luaL_checkstring(L,-2);
           (*pa)[i].nsap.nsapaddress = luaL_checkstring(L,-1);
           break;
           
      case RR_ISDN:
           lua_getfield(L,tidx,"address");
           lua_getfield(L,tidx,"sa");
           (*pa)[i].isdn.isdnaddress = luaL_checkstring(L,-2);
           (*pa)[i].isdn.sa          = luaL_checkstring(L,-1);
           break;
           
      case RR_HINFO:
           lua_getfield(L,tidx,"cpu");
           lua_getfield(L,tidx,"os");
           (*pa)[i].hinfo.cpu = luaL_checkstring(L,-2);
           (*pa)[i].hinfo.os  = luaL_checkstring(L,-1);
           break;
           
      case RR_X25:
           lua_getfield(L,tidx,"address");
           (*pa)[i].x25.psdnaddress = luaL_checklstring(L,-1,&(*pa)[i].x25.size);
           break;
           
      case RR_SPF:
           lua_getfield(L,tidx,"text");
           (*pa)[i].spf.text = luaL_checklstring(L,-1,&(*pa)[i].spf.len);
           break;
           
      case RR_TXT:
           lua_getfield(L,tidx,"text");
           (*pa)[i].txt.text = luaL_checklstring(L,-1,&(*pa)[i].txt.len);
           break;
           
      case RR_NSAP_PTR:
           lua_getfield(L,tidx,"owner");
           (*pa)[i].nsap_ptr.owner = luaL_checkstring(L,-1);
           break;
           
      case RR_MD:
           lua_getfield(L,tidx,"madname");
           (*pa)[i].md.madname = luaL_checkstring(L,-1);
           break;
           
      case RR_MF:
           lua_getfield(L,tidx,"madname");
           (*pa)[i].mf.madname = luaL_checkstring(L,-1);
           break;
           
      case RR_MB:
           lua_getfield(L,tidx,"madname");
           (*pa)[i].mb.madname = luaL_checkstring(L,-1);
           break;
           
      case RR_MG:
           lua_getfield(L,tidx,"mgmname");
           (*pa)[i].mg.mgmname = luaL_checkstring(L,-1);
           break;
           
      case RR_MR:
           lua_getfield(L,tidx,"newname");
           (*pa)[i].mr.newname = luaL_checkstring(L,-1);
           break;
           
      case RR_NS:
           lua_getfield(L,tidx,"nsdname");
           (*pa)[i].ns.nsdname = luaL_checkstring(L,-1);
           break;
           
      case RR_PTR:
           lua_getfield(L,tidx,"ptr");
           (*pa)[i].ptr.ptr = luaL_checkstring(L,-1);
           break;
           
      case RR_CNAME:
           lua_getfield(L,tidx,"cname");
           (*pa)[i].cname.cname = luaL_checkstring(L,-1);
           break;
           
      case RR_NULL:
           lua_getfield(L,tidx,"data");
           (*pa)[i].null.data = (uint8_t *)luaL_checklstring(L,-1,&(*pa)[i].null.size);
           break;
           
      case RR_OPT:
           lua_getfield(L,tidx,"udp_payload");
           lua_getfield(L,tidx,"version");
           lua_getfield(L,tidx,"fdo");
           lua_getfield(L,tidx,"fug");
           lua_getfield(L,tidx,"z");
           lua_getfield(L,tidx,"opts");
           
           (*pa)[i].opt.udp_payload = luaL_checkinteger(L,-6);
           (*pa)[i].opt.version     = luaL_checkinteger(L,-5);
           (*pa)[i].opt.fdo         = lua_toboolean(L,-4);
           (*pa)[i].opt.fug         = luaL_optinteger(L,-3,0);
           (*pa)[i].opt.z           = luaL_optinteger(L,-2,0);
           (*pa)[i].opt.numopts     = lua_rawlen(L,-1);
           (*pa)[i].opt.opts        = lua_newuserdata(L,(*pa)[i].opt.numopts * sizeof(edns0_opt_t));
           
           for (size_t j = 0 ; j < (*pa)[i].opt.numopts ; j++)
           {
             lua_pushinteger(L,j + 1);
             lua_gettable(L,-3);
             lua_getfield(L,-1,"data");
             lua_getfield(L,-2,"code");
             
             (*pa)[i].opt.opts[j].data = (uint8_t *)luaL_checklstring(L,-2,&(*pa)[i].opt.opts[j].len);
             if (lua_isnumber(L,-1))
               (*pa)[i].opt.opts[j].code = lua_tointeger(L,-1);
             else if (lua_isstring(L,-1))
             {
               if (strcmp("NSID",lua_tostring(L,-1)) == 0)
                 (*pa)[i].opt.opts[j].code = EDNS0RR_NSID;
               else if (strcmp("nsid",lua_tostring(L,-1)) == 0)
                 (*pa)[i].opt.opts[j].code = EDNS0RR_NSID;
               else
                 luaL_error(L,"OPT RR code '%s' not supported",lua_tostring(L,-1));
             }
             lua_pop(L,2);
           }
           
           break;
           
      default: break;
    }
    
    lua_settop(L,top);
  }
}

/********************************************************************/

static int dnslua_encode(lua_State *L)
{
  dns_query_t  query;
  dns_packet_t buffer[DNS_BUFFER_UDP_MAX];
  size_t       len;
  dns_rcode_t  rc;
  
  luaL_checktype(L,1,LUA_TTABLE);
  lua_settop(L,1);
  
  lua_getfield(L,1,"id");
  lua_getfield(L,1,"query");
  lua_getfield(L,1,"opcode");
  lua_getfield(L,1,"aa");
  lua_getfield(L,1,"tc");
  lua_getfield(L,1,"rd");
  lua_getfield(L,1,"ra");
  lua_getfield(L,1,"z");
  lua_getfield(L,1,"ad");
  lua_getfield(L,1,"cd");
  lua_getfield(L,1,"rcode");
  
  query.id     = luaL_checkinteger(L,-11);
  query.query  = lua_toboolean(L,-10);
  query.opcode = dns_op_value(luaL_optstring(L,-9,"QUERY"));
  query.aa     = lua_toboolean(L,-8);
  query.tc     = lua_toboolean(L,-7);
  query.rd     = lua_toboolean(L,-6);
  query.ra     = lua_toboolean(L,-5);
  query.z      = lua_toboolean(L,-4);
  query.ad     = lua_toboolean(L,-3);
  query.cd     = lua_toboolean(L,-2);
  query.rcode  = dns_rcode_value(luaL_optstring(L,-1,"OKAY"));
  lua_pop(L,11);
  
  lua_getfield(L,1,"question");
  to_question(L,&query.questions,&query.qdcount,-1);
  lua_getfield(L,1,"answers");
  to_answers(L,&query.answers,&query.ancount,-1);
  lua_getfield(L,1,"nameservers");
  to_answers(L,&query.nameservers,&query.nscount,-1);
  lua_getfield(L,1,"additional");
  to_answers(L,&query.additional,&query.arcount,-1);
  
  len = sizeof(buffer);
  rc  = dns_encode(buffer,&len,&query);
  
  if (rc != RCODE_OKAY)
  {
    lua_pushnil(L);
    lua_pushinteger(L,rc);
    return 2;
  }
  
  lua_pushlstring(L,(char *)buffer,len);
  return 1;
}

/********************************************************************/

static void push_dnsgpos_angle(lua_State *L,dnsgpos_angle *pa,bool lat)
{
  lua_createtable(L,0,4);
  lua_pushinteger(L,pa->deg);
  lua_setfield(L,-2,"deg");
  lua_pushinteger(L,pa->min);
  lua_setfield(L,-2,"min");
  lua_pushnumber(L,(double)pa->sec + ((double)pa->frac / 1000.0));
  lua_setfield(L,-2,"sec");
  lua_pushboolean(L,pa->nw);
  lua_setfield(L,-2,"nw");
  if (lat)
    lua_pushlstring(L,(pa->nw) ? "N" : "S" , 1);
  else
    lua_pushlstring(L,(pa->nw) ? "W" : "E" , 1);
  lua_setfield(L,-2,"hemisphere");
}

/********************************************************************/

static void decode_answer(
        lua_State    *L,
        int           tab,
        const char   *name,
        dns_answer_t *pans,
        size_t        cnt
)
{
  char ipaddr[INET6_ADDRSTRLEN];
  
  lua_createtable(L,cnt,0);
  
  for (size_t i = 0 ; i < cnt ; i++)
  {
    lua_pushinteger(L,i + 1);
    lua_createtable(L,0,0);
    
    lua_pushstring(L,pans[i].generic.name);
    lua_setfield(L,-2,"name");
    lua_pushinteger(L,pans[i].generic.ttl);
    lua_setfield(L,-2,"ttl");
    lua_pushstring(L,dns_class_text(pans[i].generic.class));
    lua_setfield(L,-2,"class");
    lua_pushstring(L,dns_type_text(pans[i].generic.type));
    lua_setfield(L,-2,"type");
    
    switch(pans[i].generic.type)
    {
      case RR_A:
           inet_ntop(AF_INET,&pans[i].a.address,ipaddr,sizeof(ipaddr));
           lua_pushstring(L,ipaddr);
           lua_setfield(L,-2,"address");
           lua_pushlstring(L,(char *)&pans[i].a.address,4);
           lua_setfield(L,-2,"raw_address");
           break;
           
      case RR_SOA:
           lua_pushstring(L,pans[i].soa.mname);
           lua_setfield(L,-2,"mname");
           lua_pushstring(L,pans[i].soa.rname);
           lua_setfield(L,-2,"rname");
           lua_pushnumber(L,pans[i].soa.serial);
           lua_setfield(L,-2,"serial");
           lua_pushnumber(L,pans[i].soa.refresh);
           lua_setfield(L,-2,"refresh");
           lua_pushnumber(L,pans[i].soa.retry);
           lua_setfield(L,-2,"retry");
           lua_pushnumber(L,pans[i].soa.expire);
           lua_setfield(L,-2,"expire");
           lua_pushnumber(L,pans[i].soa.minimum);
           lua_setfield(L,-2,"minimum");
           break;
           
      case RR_NAPTR:
           lua_pushinteger(L,pans[i].naptr.order);
           lua_setfield(L,-2,"order");
           lua_pushinteger(L,pans[i].naptr.preference);
           lua_setfield(L,-2,"preference");
           lua_pushstring(L,pans[i].naptr.flags);
           lua_setfield(L,-2,"flags");
           lua_pushstring(L,pans[i].naptr.services);
           lua_setfield(L,-2,"services");
           lua_pushstring(L,pans[i].naptr.regexp);
           lua_setfield(L,-2,"regexp");
           lua_pushstring(L,pans[i].naptr.replacement);
           lua_setfield(L,-2,"replacement");
           break;
           
      case RR_AAAA:
           inet_ntop(AF_INET6,&pans[i].aaaa.address,ipaddr,sizeof(ipaddr));
           lua_pushstring(L,ipaddr);
           lua_setfield(L,-2,"address");
           lua_pushlstring(L,(char *)&pans[i].aaaa.address,16);
           lua_setfield(L,-2,"raw_address");
           break;
           
      case RR_SRV:
           lua_pushinteger(L,pans[i].srv.priority);
           lua_setfield(L,-2,"priority");
           lua_pushinteger(L,pans[i].srv.weight);
           lua_setfield(L,-2,"weight");
           lua_pushinteger(L,pans[i].srv.port);
           lua_setfield(L,-2,"port");
           lua_pushstring(L,pans[i].srv.target);
           lua_setfield(L,-2,"target");
           break;
           
      case RR_WKS:
           inet_ntop(AF_INET,&pans[i].wks.address,ipaddr,sizeof(ipaddr));
           lua_pushstring(L,ipaddr);
           lua_setfield(L,-2,"address");
           lua_pushlstring(L,(char *)&pans[i].wks.address,4);
           lua_setfield(L,-2,"raw_address");
           lua_pushinteger(L,pans[i].wks.protocol);
           lua_setfield(L,-2,"protocol");
           lua_pushlstring(L,(char *)pans[i].wks.bits,pans[i].wks.numbits);
           lua_setfield(L,-2,"bits");
           break;
           
      case RR_GPOS:
           push_dnsgpos_angle(L,&pans[i].gpos.latitude,true);
           lua_setfield(L,-2,"longitude");
           push_dnsgpos_angle(L,&pans[i].gpos.longitude,false);
           lua_setfield(L,-2,"latitude");
           lua_pushnumber(L,pans[i].gpos.altitude);
           lua_setfield(L,-2,"altitude");
           break;
           
      case RR_LOC:
           lua_pushnumber(L,pans[i].loc.size);
           lua_setfield(L,-2,"size");
           lua_pushnumber(L,pans[i].loc.horiz_pre);
           lua_setfield(L,-2,"horiz_pre");
           lua_pushnumber(L,pans[i].loc.vert_pre);
           lua_setfield(L,-2,"vert_pre");
           push_dnsgpos_angle(L,&pans[i].loc.latitude,true);
           lua_setfield(L,-2,"latitude");
           push_dnsgpos_angle(L,&pans[i].loc.longitude,false);
           lua_setfield(L,-2,"longitude");
           lua_pushnumber(L,pans[i].loc.altitude);
           lua_setfield(L,-2,"altitude");
           break;
           
      case RR_PX:
           lua_pushstring(L,pans[i].px.map822);
           lua_setfield(L,-2,"map822");
           lua_pushstring(L,pans[i].px.mapx400);
           lua_setfield(L,-2,"mapx400");
           break;
           
      case RR_RP:
           lua_pushstring(L,pans[i].rp.mbox);
           lua_setfield(L,-2,"mbox");
           lua_pushstring(L,pans[i].rp.domain);
           lua_setfield(L,-2,"domain");
           break;
           
      case RR_MINFO:
           lua_pushstring(L,pans[i].minfo.rmailbx);
           lua_setfield(L,-2,"rmailbx");
           lua_pushstring(L,pans[i].minfo.emailbx);
           lua_setfield(L,-2,"emailbx");
           break;
           
      case RR_AFSDB:
           lua_pushinteger(L,pans[i].afsdb.subtype);
           lua_setfield(L,-2,"subtype");
           lua_pushstring(L,pans[i].afsdb.hostname);
           lua_setfield(L,-2,"hostname");
           break;
           
      case RR_RT:
           lua_pushinteger(L,pans[i].rt.preference);
           lua_setfield(L,-2,"preference");
           lua_pushstring(L,pans[i].rt.host);
           lua_setfield(L,-2,"host");
           break;
           
      case RR_MX:
           lua_pushinteger(L,pans[i].mx.preference);
           lua_setfield(L,-2,"preference");
           lua_pushstring(L,pans[i].mx.exchange);
           lua_setfield(L,-2,"exchange");
           break;
           
      case RR_NSAP:
           lua_pushstring(L,pans[i].nsap.length);
           lua_setfield(L,-2,"length");
           lua_pushstring(L,pans[i].nsap.nsapaddress);
           lua_setfield(L,-2,"address");
           break;
           
      case RR_ISDN:
           lua_pushstring(L,pans[i].isdn.isdnaddress);
           lua_setfield(L,-2,"address");
           lua_pushstring(L,pans[i].isdn.sa);
           lua_setfield(L,-2,"sa");
           break;
           
      case RR_HINFO:
           lua_pushstring(L,pans[i].hinfo.cpu);
           lua_setfield(L,-2,"cpu");
           lua_pushstring(L,pans[i].hinfo.os);
           lua_setfield(L,-2,"os");
           break;
           
      case RR_X25:
           lua_pushlstring(L,pans[i].x25.psdnaddress,pans[i].x25.size);
           lua_setfield(L,-2,"address");
           break;
           
      case RR_SPF:
           lua_pushlstring(L,pans[i].spf.text,pans[i].spf.len);
           lua_setfield(L,-2,"text");
           break;
           
      case RR_TXT:
           lua_pushlstring(L,pans[i].txt.text,pans[i].txt.len);
           lua_setfield(L,-2,"text");
           break;
           
      case RR_NSAP_PTR:
           lua_pushstring(L,pans[i].nsap_ptr.owner);
           lua_setfield(L,-2,"owner");
           break;
           
      case RR_MD:
           lua_pushstring(L,pans[i].md.madname);
           lua_setfield(L,-2,"madname");
           break;
           
      case RR_MF:
           lua_pushstring(L,pans[i].mf.madname);
           lua_setfield(L,-2,"madname");
           break;
           
      case RR_MB:
           lua_pushstring(L,pans[i].mb.madname);
           lua_setfield(L,-2,"madname");
           break;
           
      case RR_MG:
           lua_pushstring(L,pans[i].mg.mgmname);
           lua_setfield(L,-2,"mgmname");
           break;
           
      case RR_MR:
           lua_pushstring(L,pans[i].mr.newname);
           lua_setfield(L,-2,"newname");
           break;
           
      case RR_NS:
           lua_pushstring(L,pans[i].ns.nsdname);
           lua_setfield(L,-2,"nsdname");
           break;
           
      case RR_PTR:
           lua_pushstring(L,pans[i].ptr.ptr);
           lua_setfield(L,-2,"ptr");
           break;
           
      case RR_CNAME:
           lua_pushstring(L,pans[i].cname.cname);
           lua_setfield(L,-2,"cname");
           break;
           
      case RR_NULL:
           lua_pushlstring(L,(char *)pans[i].null.data,pans[i].null.size);
           lua_setfield(L,-2,"data");
           break;
           
      case RR_OPT:
           lua_pushinteger(L,pans[i].opt.udp_payload);
           lua_setfield(L,-2,"udp_payload");
           lua_pushinteger(L,pans[i].opt.version);
           lua_setfield(L,-2,"version");
           lua_pushboolean(L,pans[i].opt.fdo);
           lua_setfield(L,-2,"fdo");
           lua_pushinteger(L,pans[i].opt.fug);
           lua_setfield(L,-2,"fug");
           lua_pushinteger(L,pans[i].opt.z);
           lua_setfield(L,-2,"z");
           lua_createtable(L,pans[i].opt.numopts,0);
           for (size_t j = 0 ; j < pans[i].opt.numopts ; j++)
           {
             lua_pushinteger(L,j + 1);
             lua_createtable(L,0,2);
             lua_pushlstring(L,(char *)pans[i].opt.opts[j].data,pans[i].opt.opts[j].len);
             lua_setfield(L,-2,"data");
             if (pans[i].opt.opts[j].code == EDNS0RR_NSID)
               lua_pushstring(L,"NSID");
             else
               lua_pushinteger(L,pans[i].opt.opts[j].code);
             lua_setfield(L,-2,"code");
             lua_settable(L,-3);
           }
           lua_setfield(L,-2,"opts");
           break;
           
      default:
           lua_pushlstring(L,(char *)pans[i].x.rawdata,pans[i].x.size);
           lua_setfield(L,-2,"rawdata");
           break;
    }
    
    lua_settable(L,-3);
  }
  
  lua_setfield(L,tab,name);
}

/**********************************************************************/

static int dnslua_decode(lua_State *L)
{
  dns_decoded_t      bufresult[DNS_DECODEBUF_8K];
  dns_packet_t       data     [DNS_DECODEBUF_4K];
  const char        *luadata;
  dns_query_t       *result;
  size_t             size;
  int                tab;
  int                rc;
  
  /*---------------------------------------------------------------------
  ; We need to make sure our data is properly aligned.  And hey, this is
  ; Lua---a scripting lanague.  We can afford a bit of waste 8-)
  ;----------------------------------------------------------------------*/
  
  luadata = luaL_checklstring(L,1,&size);
  if (size > sizeof(data)) size = sizeof(data);
  memcpy(data,luadata,size);
  
  rc = dns_decode(bufresult,&(size_t){sizeof(bufresult)},data,size);
  
  if (rc != RCODE_OKAY)
  {
    lua_pushnil(L);
    lua_pushinteger(L,rc);
    return 2;
  }
  
  result = (dns_query_t *)bufresult;
  
  lua_createtable(L,0,0);
  tab = lua_gettop(L);
  
  lua_pushinteger(L,result->id);
  lua_setfield(L,tab,"id");
  lua_pushboolean(L,result->query);
  lua_setfield(L,tab,"query");
  lua_pushstring(L,dns_op_text(result->opcode));
  lua_setfield(L,tab,"opcode");
  lua_pushboolean(L,result->aa);
  lua_setfield(L,tab,"aa");
  lua_pushboolean(L,result->tc);
  lua_setfield(L,tab,"tc");
  lua_pushboolean(L,result->rd);
  lua_setfield(L,tab,"rd");
  lua_pushboolean(L,result->ra);
  lua_setfield(L,tab,"ra");
  lua_pushboolean(L,result->z);
  lua_setfield(L,tab,"z");
  lua_pushboolean(L,result->ad);
  lua_setfield(L,tab,"ad");
  lua_pushboolean(L,result->cd);
  lua_setfield(L,tab,"cd");
  lua_pushstring(L,dns_rcode_enum(result->rcode));
  lua_setfield(L,tab,"rcode");
  
  if (result->qdcount)
  {
    lua_createtable(L,0,3);
    lua_pushstring(L,result->questions[0].name);
    lua_setfield(L,-2,"name");
    lua_pushstring(L,dns_class_text(result->questions[0].class));
    lua_setfield(L,-2,"class");
    lua_pushstring(L,dns_type_text(result->questions[0].type));
    lua_setfield(L,-2,"type");
    lua_setfield(L,tab,"question");
  }
  
  decode_answer(L,tab,"answers"     , result->answers    , result->ancount);
  decode_answer(L,tab,"nameservers" , result->nameservers, result->nscount);
  decode_answer(L,tab,"additional"  , result->additional , result->arcount);
  
  assert(tab == lua_gettop(L));
  
  return 1;
}

/*********************************************************************/

static int dnslua_strerror(lua_State *L)
{
  lua_pushstring(L,dns_rcode_text(luaL_checkinteger(L,1)));
  return 1;
}

/*********************************************************************/

static int dnslua_query(lua_State *L)
{
  sockaddr_all  srvaddr;
  const char   *server;
  const char   *luaquery;
  size_t        querysize;
  dns_packet_t  query[DNS_BUFFER_UDP_MAX];
  dns_packet_t  reply[DNS_DECODEBUF_4K];
  size_t        replysize;
  int           rc;
  
  server   = luaL_checkstring(L,1);
  luaquery = luaL_checklstring(L,2,&querysize);
  
  if (net_server(&srvaddr,server) < 0)
    luaL_error(L,"%s is not an IPv4/IPv6 address",server);
    
  if (querysize > MAX_DNS_QUERY_SIZE) querysize = MAX_DNS_QUERY_SIZE;
  memcpy(query,luaquery,querysize);
  replysize = sizeof(reply);
  rc = net_request(&srvaddr,reply,&replysize,query,querysize);
  
  if (rc != 0)
  {
    lua_pushnil(L);
    lua_pushinteger(L,rc);
    return 2;
  }
  
  lua_pushlstring(L,(char *)reply,replysize);
  return 1;
}

/**********************************************************************/

static const struct luaL_Reg reg_dns[] =
{
  { "encode"    , dnslua_encode         } ,
  { "decode"    , dnslua_decode         } ,
  { "strerror"  , dnslua_strerror       } ,
  { "query"     , dnslua_query          } ,
  { NULL        , NULL                  }
};

int luaopen_org_conman_dns(lua_State *L)
{
#if LUA_VERSION_NUM == 501
  luaL_register(L,"org.conman.dns",reg_dns);
#else
  luaL_newlib(L,reg_dns);
#endif

  lua_pushliteral(L,"Copyright 2010 by Sean Conner.  All Rights Reserved.");
  lua_setfield(L,-2,"COPYRIGHT");
  
  lua_pushliteral(L,"Encode/Decode and send queries via DNS");
  lua_setfield(L,-2,"DESCRIPTION");
  
  lua_pushliteral(L,VERSION);
  lua_setfield(L,-2,"_VERSION");
  
  return 1;
}

/**********************************************************************/
