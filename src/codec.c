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
* Implements the code to encode a DNS query (*NOTE* only queries at this
* time) and to decode responses from a DNS server.  This exports two
* functions:
*
*  dns_encode()
*
*       This function takes a filled in dns_query_t structure (assumed to be
*       filled out correctly and creates the wire representation of that
*       query into a buffer supplied to the routine.
*
*       THIS ROUTINE DOES NOT ALLOCATE MEMORY, NOR DOES IT USE GLOBAL
*       VARAIBLES. IT IS THEREFORE THREAD SAFE.
*
*       See test.c for an example of calling this routine.
*
*  dns_decode()
*
*       This function takes the wire representation of a response, decodes
*       and returns a dns_query_t filled out with the various records.  You
*       supply a block of memory sufficient enough to store the dns_query_t
*       and any various strings/structures used in the dns_query_t (I've
*       found 8K to be more than enough for decoding a UDP response but
*       that's a very conservative value; 4K may be good enough).
*
*       THIS ROUTINE DOES NOT ALLOCATE MEMORY, NOR DOES IT USE GLOBAL
*       VARIABLES.  IT IS THEREFORE THREAD SAFE.
*
*       See test.c for an example of calling this routine.
*
*       This code is written using C99.
*
* The code in here requires no other code from this project.
*
****************************************************************************/

#define _GNU_SOURCE

#include <limits.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <math.h>
#include <assert.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include "dns.h"

/*----------------------------------------------------------------------------
; The folowing are used for memory allocation.  dns_decoded_t should be fine
; for alignment size, as it's good enough for alignment.  If some odd-ball
; system comes up that requires more strict alignment, then I'll change this
; to something like a long double or something silly like that.
;
; see the comment align_memory() for more details
;-----------------------------------------------------------------------------*/

#define MEM_ALIGN       sizeof(dns_decoded_t)
#define MEM_MASK        ~(sizeof(dns_decoded_t) - 1uL)

/*---------------------------------------------------------------------------
; This is the maximum number of domain labels to encode.  The domain
; "example.com" contains two domain labels.  "1.0.0.127.in-addr.arpa" has
; six domain labels.  This value is an arbitrary limit to avoid doing any
; memory allocations but I feel it's sufficiently large enough to avoid any
; limits.  I hope.
;----------------------------------------------------------------------------*/

#define MAXSEG  100

/*---------------------------------------------------------------------------
; You really, no, I mean it, *REALLY* need to read RFC-1876 to understand
; all the crap that's going on for deciphering RR_LOC.
;----------------------------------------------------------------------------*/

#define LOC_BIAS        (((unsigned long)INT32_MAX) + 1uL)
#define LOC_LAT_MAX     ((unsigned long)( 90uL * 3600000uL))
#define LOC_LNG_MAX     ((unsigned long)(180uL * 3600000uL))
#define LOC_ALT_BIAS    (10000000L)

/************************************************************************/

struct idns_header
{
  uint16_t id;
  uint8_t  opcode;
  uint8_t  rcode;
  uint16_t qdcount;
  uint16_t ancount;
  uint16_t nscount;
  uint16_t arcount;
} __attribute__ ((packed));

struct segment
{
  char const *name;
  size_t      offset;
};

typedef struct block
{
  size_t   size;
  uint8_t *ptr;
} block__s;

typedef struct segments
{
  size_t idx;
  struct segment seg[MAXSEG];
} segments__s;

typedef struct edns_context
{
  block__s     packet;
  segments__s  segments;
  bool         rropt;
  uint8_t     *base;
  dns_rcode_t  rcode;
} edns_context;

typedef struct ddns_context
{
  block__s     packet;
  block__s     parse;
  block__s     dest;    /* see comments in align_memory() */
  dns_query_t *response;
  bool         edns;
} ddns_context;

/***********************************************************************/

#ifndef NDEBUG
  static int query_okay(dns_query_t const *query)
  {
    assert(query          != NULL);
    assert(query->id      >= 0);
    assert(query->id      <= UINT16_MAX);
    assert(query->opcode  <= 2);
    assert(query->rcode   <= 5);
    assert(query->qdcount <= UINT16_MAX);
    assert(query->ancount <= UINT16_MAX);
    assert(query->nscount <= UINT16_MAX);
    assert(query->arcount <= UINT16_MAX);
    
    if (query->query)
    {
      assert((query->opcode == OP_QUERY) || (query->opcode == OP_IQUERY));
      assert(!query->aa);
      assert(!query->tc);
      assert(!query->ra);
      assert(query->rcode == RCODE_OKAY);
    }
    return 1;
  }
  
  static int pblock_okay(block__s const *block)
  {
    assert(block       != NULL);
    assert(block->ptr  != NULL);
    assert(block->size >  0);
    return 1;
  }
  
  static int block_okay(block__s const block)
  {
    assert(block.ptr  != NULL);
    assert(block.size >  0);
    return 1;
  }
  
  static int econtext_okay(edns_context const *data)
  {
    assert(data != NULL);
    assert(block_okay(data->packet));
    assert(data->base != NULL);
    return 1;
  }
  
  static int dcontext_okay(ddns_context const *data)
  {
    assert(data           != NULL);
    assert(data->response != NULL);
    assert(block_okay(data->packet));
    assert(block_okay(data->parse));
    assert(block_okay(data->dest));
    return 1;
  }
#endif

/*******************************************************************/

static inline void write_uint16(block__s *parse,uint16_t value)
{
  assert(pblock_okay(parse));
  assert(parse->size >= 2);
  
  parse->ptr[0]  = (value >> 8) & 0xFF;
  parse->ptr[1]  = (value     ) & 0xFF;
  parse->ptr    += 2;
  parse->size   -= 2;
}

/***********************************************************************/

static inline void write_uint32(block__s *parse,uint32_t value)
{
  assert(pblock_okay(parse));
  assert(parse->size >= 4);
  
  parse->ptr[0]  = (value >> 24) & 0xFF;
  parse->ptr[1]  = (value >> 16) & 0xFF;
  parse->ptr[2]  = (value >>  8) & 0xFF;
  parse->ptr[3]  = (value      ) & 0xFF;
  parse->ptr    += 4;
  parse->size   -= 4;
}

/***********************************************************************/

static struct segment const *segment_find(char const *src,segments__s const *seg)
{
  assert(src != NULL);
  assert(seg != NULL);
  
  for (size_t i = 0 ; i < seg->idx ; i++)
    if (strcmp(src,seg->seg[i].name) == 0)
      return &seg->seg[i];
      
  return NULL;
}

/***********************************************************************/

static dns_rcode_t encode_segment(char const **psrc,uint8_t const *base,block__s *block,size_t *offset)
{
  assert(psrc   != NULL);
  assert(*psrc  != NULL);
  assert(base   != NULL);
  assert(block  != NULL);
  assert(offset != NULL);
  
  char *p = strchr(*psrc,'.');
  
  if (p == NULL)
    return RCODE_NAME_ERROR;
    
  size_t len = p - *psrc;
  
  if (len >= MAX_DOMAIN_LABEL)
    return RCODE_NAME_ERROR;
    
  if (block->size < len + 1)
    return RCODE_NO_MEMORY;
    
  *offset       = (size_t)(block->ptr - base);
  *block->ptr++ = (uint8_t)len;
  
  memcpy(block->ptr,*psrc,len);
  
  block->ptr  += len;
  block->size -= (len + 1);
  *psrc        = p + 1;
  
  return RCODE_OKAY;
}

/***********************************************************************/

static dns_rcode_t encode_domain(
        edns_context *data,
        char const   *name
)
{
  struct segment const *segment;
  dns_rcode_t           rc;
  
  assert(econtext_okay(data));
  assert(name != NULL);
  
  while((*name != '.') && (*name != '\0'))
  {
    assert(*name != '.');
    segment = segment_find(name,&data->segments);
    if (segment == NULL)
    {
      if (data->segments.idx == MAXSEG)
        return RCODE_NO_MEMORY;
        
      data->segments.seg[data->segments.idx].name = name;
      rc = encode_segment(&name,data->base,&data->packet,&data->segments.seg[data->segments.idx].offset);
      
      if (rc != RCODE_OKAY)
        return rc;
        
      data->segments.idx++;
    }
    else
    {
      if (data->packet.size < 2)
        return RCODE_NO_MEMORY;
      *data->packet.ptr++  = (uint8_t)(segment->offset >> 8) | 0xC0;
      *data->packet.ptr++  = (uint8_t)segment->offset;
      data->packet.size   -= 2;
      return RCODE_OKAY;
    }
  }
  
  if (data->packet.size == 0)
    return RCODE_NO_MEMORY;
    
  *data->packet.ptr++ = 0;
  data->packet.size--;
  return RCODE_OKAY;
}

/*******************************************************************/

static dns_rcode_t encode_string(
        edns_context *data,
        char const   *text,
        size_t        size
)
{
  assert(econtext_okay(data));
  assert(text != NULL);
  
  if (size > 255)                   return RCODE_BAD_STRING;
  if (data->packet.size < size + 1) return RCODE_NO_MEMORY;
  
  *data->packet.ptr++ = size;
  memcpy(data->packet.ptr,text,size);
  data->packet.ptr += size;
  data->packet.size -= (size + 1);
  
  return RCODE_OKAY;
}

/******************************************************************/

static dns_rcode_t encode_question(
        edns_context         *data,
        dns_question_t const *pquestion
)
{
  int rc;
  
  assert(econtext_okay(data));
  assert(pquestion        != NULL);
  assert(pquestion->name  != NULL);
  assert(pquestion->type  != RR_OPT);
  assert(pquestion->class >= 1);
  assert(pquestion->class <= 4);
  
  rc = encode_domain(data,pquestion->name);
  if (rc != RCODE_OKAY)
    return rc;
    
  if (data->packet.size < 4)
    return RCODE_NO_MEMORY;
    
  write_uint16(&data->packet,pquestion->type);
  write_uint16(&data->packet,pquestion->class);
  
  return RCODE_OKAY;
}

/*************************************************************************/

static inline dns_rcode_t encode_rr_a(edns_context *data,dns_a_t const *a)
{
  assert(econtext_okay(data));
  assert(a != NULL);
  
  if (data->packet.size < 4)
    return RCODE_NO_MEMORY;
    
  memcpy(data->packet.ptr,&a->address,4);
  data->packet.ptr  += 4;
  data->packet.size -= 4;
  return RCODE_OKAY;
}

/*************************************************************************/

static inline dns_rcode_t encode_rr_soa(edns_context *data,dns_soa_t const *soa)
{
  dns_rcode_t rc;
  
  assert(econtext_okay(data));
  assert(soa        != NULL);
  assert(soa->mname != NULL);
  assert(soa->rname != NULL);
  
  if ((rc = encode_domain(data,soa->mname)) != RCODE_OKAY) return rc;
  if ((rc = encode_domain(data,soa->rname)) != RCODE_OKAY) return rc;
  
  if (data->packet.size < 20)
    return RCODE_NO_MEMORY;
    
  write_uint32(&data->packet,soa->serial);
  write_uint32(&data->packet,soa->refresh);
  write_uint32(&data->packet,soa->retry);
  write_uint32(&data->packet,soa->expire);
  write_uint32(&data->packet,soa->minimum);
  
  return RCODE_OKAY;
}

/*************************************************************************/

static inline dns_rcode_t encode_rr_aaaa(edns_context *data,dns_aaaa_t const *aaaa)
{
  assert(econtext_okay(data));
  assert(aaaa != NULL);
  
  if (data->packet.size < 16)
    return RCODE_NO_MEMORY;
    
  memcpy(data->packet.ptr,&aaaa->address,16);
  data->packet.ptr  += 16;
  data->packet.size -= 16;
  return RCODE_OKAY;
}

/*************************************************************************/

static inline dns_rcode_t encode_rr_srv(edns_context *data,dns_srv_t const *srv)
{
  assert(econtext_okay(data));
  assert(srv           != NULL);
  assert(srv->priority <= UINT16_MAX);
  assert(srv->weight   <= UINT16_MAX);
  assert(srv->port     <= UINT16_MAX);
  assert(srv->target   != NULL);
  
  if (data->packet.size < 7)
    return RCODE_NO_MEMORY;
    
  write_uint16(&data->packet,srv->priority);
  write_uint16(&data->packet,srv->weight);
  write_uint16(&data->packet,srv->port);
  return encode_domain(data,srv->target);
}

/*************************************************************************/

static inline dns_rcode_t encode_rr_wks(edns_context *data,dns_wks_t const *wks)
{
  assert(econtext_okay(data));
  assert(wks           != NULL);
  assert(wks->protocol <= UINT16_MAX);
  assert(wks->numbits  <= 8192);
  assert(wks->bits     != NULL);
  
  if (data->packet.size < wks->numbits + 6)
    return RCODE_NO_MEMORY;
    
  memcpy(data->packet.ptr,&wks->address,4);
  data->packet.ptr  += 4;
  data->packet.size -= 4;
  write_uint16(&data->packet,wks->protocol);
  memcpy(data->packet.ptr,wks->bits,wks->numbits);
  data->packet.ptr  += wks->numbits;
  data->packet.size -= wks->numbits;
  return RCODE_OKAY;
}

/*************************************************************************/

static inline dns_rcode_t encode_rr_gpos(edns_context *data,dns_gpos_t const *gpos)
{
  dns_rcode_t rc;
  double      lat;
  double      lng;
  char        text[12];
  int         textlen;
  
  assert(econtext_okay(data));
  assert(gpos                 != NULL);
  assert(gpos->longitude.deg  <=  180);
  assert(gpos->longitude.min  <    60);
  assert(gpos->longitude.sec  <    60);
  assert(gpos->longitude.frac <  1000);
  assert(gpos->latitude.deg   <=   90);
  assert(gpos->latitude.min   <    60);
  assert(gpos->latitude.sec   <    60);
  assert(gpos->latitude.frac  <  1000);
  
  lat = (double)gpos->latitude.deg
      + (double)gpos->latitude.min  /      60.0
      + (double)gpos->latitude.sec  /    3600.0
      + (double)gpos->latitude.frac / 3600000.0
      ;
  if (!gpos->latitude.nw) lat = -lat;
  
  lng = (double)gpos->longitude.deg
      + (double)gpos->longitude.min  /      60.0
      + (double)gpos->longitude.sec  /    3600.0
      + (double)gpos->longitude.frac / 3600000.0
      ;
  if (gpos->longitude.nw) lng = -lng;
  
  textlen = snprintf(text,sizeof(text),"%f",lng);
  if ((rc = encode_string(data,text,textlen)) != RCODE_OKAY)
    return rc;
    
  textlen = snprintf(text,sizeof(text),"%f",lat);
  if ((rc = encode_string(data,text,textlen)) != RCODE_OKAY)
    return rc;
    
  textlen = snprintf(text,sizeof(text),"%f",gpos->altitude);
  return encode_string(data,text,textlen);
}

/*************************************************************************
*
* You really, no, I mean it, *REALLY* need to read RFC-1876 to understand
* all the crap that's going on for deciphering RR_LOC.
*
**************************************************************************/

static uint8_t eloc_scale(unsigned long long scale,unsigned long def)
{
  double fp;
  double ip;
  double rs;
  int    smul;
  int    spow;
  
  if (scale == 0)
    scale = def;
    
  fp   = modf(log10(scale),&ip);
  rs   = pow(10.0,ip);
  smul = (double)scale / rs;
  spow = ip;
  
  assert(smul >= 0);
  assert(smul <= 9);
  assert(spow >= 0);
  assert(spow <= 9);
  
  return (smul << 4) | spow;
}

/*************************************************************************/

static inline dns_rcode_t encode_rr_loc(edns_context *data,dns_loc_t const *loc)
{
  uint32_t v;
  
  assert(econtext_okay(data));
  assert(loc != NULL);
  assert(loc->size           <= 9000000000uLL);
  assert(loc->horiz_pre      <= 9000000000uLL);
  assert(loc->vert_pre       <= 9000000000uLL);
  assert(loc->latitude.deg   <=  180);
  assert(loc->longitude.min  <    60);
  assert(loc->longitude.sec  <    60);
  assert(loc->longitude.frac <  1000);
  assert(loc->latitude.deg   <=   90);
  assert(loc->latitude.min   <    60);
  assert(loc->latitude.sec   <    60);
  assert(loc->latitude.frac  <  1000);
  
  if (data->packet.size < 16)
    return RCODE_NO_MEMORY;
    
  *data->packet.ptr++ = 0; /* version is always 0 */
  *data->packet.ptr++ = eloc_scale(loc->size,     100uL);
  *data->packet.ptr++ = eloc_scale(loc->horiz_pre,1000000uL);
  *data->packet.ptr++ = eloc_scale(loc->vert_pre, 1000uL);
  
  v = loc->latitude.deg * 3600000uL
    + loc->latitude.min *   60000uL
    + loc->latitude.sec *    1000uL
    + loc->latitude.frac
    ;
  assert(v <= LOC_LAT_MAX); /* above asserts should mean this is true */
  if (loc->latitude.nw)
    v += LOC_BIAS;
  else
    v = LOC_BIAS - v;
    
  write_uint32(&data->packet,v);
  
  v = loc->longitude.deg * 3600000uL
    + loc->longitude.min *   60000uL
    + loc->longitude.sec *    1000uL
    + loc->longitude.frac
    ;
  assert(v <= LOC_LNG_MAX); /* above asserts should mean this is true */
  if (!loc->longitude.nw)
    v += LOC_BIAS;
  else
    v = LOC_BIAS - v;
    
  write_uint32(&data->packet,v);
  
  write_uint32(&data->packet,(unsigned)loc->altitude + LOC_ALT_BIAS);
  return RCODE_OKAY;
}

/*************************************************************************/

static inline dns_rcode_t encode_edns0rr_nsid(
        edns_context      *data,
        edns0_opt_t const *opt
)
{
  size_t newlen;
  
  assert(econtext_okay(data));
  assert(opt       != NULL);
  assert(opt->code == EDNS0RR_NSID);
  assert(opt->len  <= UINT16_MAX);
  
  /*------------------------------------------------------------------------
  ; RFC-5001 specifies that the data for an NSID RR is the hexstring of the
  ; data, and no other meaning from the strings is to be inferred.  So we
  ; encode the data to save you from doing it.
  ;------------------------------------------------------------------------*/
  
  newlen = opt->len * 2;
  if (data->packet.size < newlen + sizeof(uint16_t) + sizeof(uint16_t))
    return RCODE_NO_MEMORY;
    
  char   buffer[newlen + 1];
  size_t nidx;
  size_t i;
  
  for (i = nidx = 0 ; i < opt->len ; i++ , nidx += 2)
    sprintf(&buffer[nidx],"%02X",opt->data[i]);
    
  assert(newlen == strlen(buffer));
  
  write_uint16(&data->packet,opt->code);
  write_uint16(&data->packet,newlen);
  memcpy(data->packet.ptr,buffer,newlen);
  data->packet.ptr  += newlen;
  data->packet.size -= newlen;
  return RCODE_OKAY;
}

/**********************************************************************/

static inline dns_rcode_t encode_edns0rr_raw(
        edns_context      *data,
        edns0_opt_t const *opt
)
{
  assert(econtext_okay(data));
  assert(opt       != NULL);
  assert(opt->code <= UINT16_MAX);
  assert(opt->len  <= UINT16_MAX);
  
  if (data->packet.size < opt->len + sizeof(uint16_t) + sizeof(uint16_t))
    return RCODE_NO_MEMORY;
    
  write_uint16(&data->packet,opt->code);
  write_uint16(&data->packet,opt->len);
  memcpy(data->packet.ptr,opt->data,opt->len);
  data->packet.ptr  += opt->len;
  data->packet.size -= opt->len;
  return RCODE_OKAY;
}

/*************************************************************************/

static inline dns_rcode_t encode_rr_opt(
        edns_context         *data,
        dns_edns0opt_t const *opt
)
{
  assert(econtext_okay(data));
  assert(opt              != NULL);
  assert(opt->class       == opt->udp_payload);
  assert(opt->ttl         == 0);
  assert(opt->version     == 0);
  assert(opt->udp_payload <= UINT16_MAX);
  
  if (data->rropt)
    return RCODE_FORMAT_ERROR; /* there can be only one! */
    
  if (data->packet.size < 11)
    return RCODE_NO_MEMORY;
    
  data->rropt = true;
  
  for (size_t i = 0 ; i < opt->numopts; i++)
  {
    dns_rcode_t rc;
    
    switch(opt->opts[i].code)
    {
      case EDNS0RR_NSID: rc = encode_edns0rr_nsid(data,&opt->opts[i]); break;
      default:           rc = encode_edns0rr_raw (data,&opt->opts[i]); break;
    }
    
    if (rc != RCODE_OKAY) return rc;
  }
  
  return RCODE_OKAY;
}

/***********************************************************************/

static inline dns_rcode_t encode_rr_naptr(
        edns_context      *data,
        dns_naptr_t const *naptr
)
{
  dns_rcode_t  rc;
  
  assert(econtext_okay(data));
  assert(naptr              != NULL);
  assert(naptr->type        == RR_NAPTR);
  assert(naptr->class       == CLASS_IN);
  assert(naptr->order       >= 0);
  assert(naptr->order       <= UINT16_MAX);
  assert(naptr->preference  >= 0);
  assert(naptr->preference  <= UINT16_MAX);
  assert(naptr->flags       != NULL);
  assert(naptr->services    != NULL);
  assert(naptr->regexp      != NULL);
  assert(naptr->replacement != NULL);
  
  if (data->packet.size < 4)
    return RCODE_NO_MEMORY;
    
  write_uint16(&data->packet,naptr->order);
  write_uint16(&data->packet,naptr->preference);
  
  if ((rc = encode_string(data,naptr->flags,   strlen(naptr->flags)))    != RCODE_OKAY) return rc;
  if ((rc = encode_string(data,naptr->services,strlen(naptr->services))) != RCODE_OKAY) return rc;
  if ((rc = encode_string(data,naptr->regexp,  strlen(naptr->regexp)))   != RCODE_OKAY) return rc;
  if ((rc = encode_domain(data,naptr->replacement))                      != RCODE_OKAY) return rc;
  
  return RCODE_OKAY;
}

/***********************************************************************/

static inline dns_rcode_t encode_rr_minfo(edns_context *data,dns_minfo_t const *minfo)
{
  dns_rcode_t rc;
  
  assert(econtext_okay(data));
  assert(minfo          != NULL);
  assert(minfo->rmailbx != NULL);
  assert(minfo->emailbx != NULL);
  
  if ((rc = encode_domain(data,minfo->rmailbx)) != RCODE_OKAY)
    return rc;
  return encode_domain(data,minfo->emailbx);
}

/*************************************************************************/

static inline dns_rcode_t encode_rr_mx(edns_context *data,dns_mx_t const *mx)
{
  assert(econtext_okay(data));
  assert(mx             != NULL);
  assert(mx->preference <= UINT16_MAX);
  assert(mx->exchange   != NULL);
  
  if (data->packet.size < 2)
    return RCODE_NO_MEMORY;
    
  write_uint16(&data->packet,mx->preference);
  return encode_domain(data,mx->exchange);
}

/*************************************************************************/

static inline dns_rcode_t encode_rr_hinfo(edns_context *data,dns_hinfo_t const *hinfo)
{
  dns_rcode_t rc;
  
  assert(econtext_okay(data));
  assert(hinfo      != NULL);
  assert(hinfo->cpu != NULL);
  assert(hinfo->os  != NULL);
  
  if ((rc = encode_string(data,hinfo->cpu,strlen(hinfo->cpu))) != RCODE_OKAY)
    return rc;
  return encode_string(data,hinfo->os,strlen(hinfo->os));
}

/*************************************************************************/

static inline dns_rcode_t encode_rr_txt(edns_context *data,dns_txt_t const *txt)
{
  char const  *p;
  size_t       max;
  dns_rcode_t  rc;
  
  assert(econtext_okay(data));
  assert(txt       != NULL);
  assert(txt->len  >  0);
  assert(txt->text != NULL);
  
  /*------------------------------------------------------------------------
  ; Text can be longer than 255 characters, but can only be encoded into 255
  ; byte chunks.
  ;-------------------------------------------------------------------------*/
  
  for (p = txt->text , max = txt->len ; max > 0 ; )
  {
    size_t chunk = (max < 255) ? max : 255;
    if ((rc = encode_string(data,p,chunk)) != RCODE_OKAY)
      return rc;
    max -= chunk;
    p   += chunk;
  }
  
  return RCODE_OKAY;
}

/*************************************************************************/

static inline dns_rcode_t encode_rr_x(edns_context *data,dns_x_t const *x)
{
  assert(econtext_okay(data));
  assert(x          != NULL);
  assert(x->rawdata != NULL);
  
  if (data->packet.size < x->size)
    return RCODE_NO_MEMORY;
    
  memcpy(data->packet.ptr,x->rawdata,x->size);
  data->packet.ptr  += x->size;
  data->packet.size -= x->size;
  
  return RCODE_OKAY;
}

/*************************************************************************/

static dns_rcode_t encode_answer(
                edns_context *data,
                dns_answer_t *answer
)
{
  dns_rcode_t  rc;
  uint8_t     *prdlen;
  uint8_t     *pdata;
  
  assert(econtext_okay(data));
  assert(answer != NULL);
  
  rc = encode_domain(data,answer->generic.name);
  if (rc != RCODE_OKAY)
    return rc;
    
  if (data->packet.size < 10)
    return RCODE_NO_MEMORY;
    
  /*------------------------------------------------------------------------
  ; For the RR OPT, the class field is actually the size of the UDP payload,
  ; and the TTL field are a bunch of flags.  We have a separate field for
  ; the UDP payload size, so here we make the adjustment behind the scenes
  ; so you don't have to know this crap.
  ;-------------------------------------------------------------------------*/
  
  if (answer->generic.type == RR_OPT)
  {
    answer->opt.class = answer->opt.udp_payload;
    answer->opt.ttl   = ((data->rcode >> 4)  & 0xFF)    << 24
                      | (answer->opt.version & 0xFF)    << 16
                      | (answer->opt.fdo ? 0x80 : 0x00) <<  8
                      ;
  }
  
  write_uint16(&data->packet,answer->generic.type);
  write_uint16(&data->packet,answer->generic.class);
  write_uint32(&data->packet,answer->generic.ttl);
  
  /*-------------------------------------------------------------------------
  ; we need to come back to the rdlen after we've written the data.  We save
  ; a pointer to this point in the output block, allocate enough space for
  ; it, then save the start of the space we're about to write to, so later
  ; we can come back and write the length.
  ;-------------------------------------------------------------------------*/
  
  prdlen             = data->packet.ptr;
  data->packet.ptr  += sizeof(uint16_t);
  data->packet.size -= sizeof(uint16_t);
  pdata              = data->packet.ptr;
  
  switch(answer->generic.type)
  {
    case RR_A:     rc = encode_rr_a    (data,&answer->a);     break;
    case RR_SOA:   rc = encode_rr_soa  (data,&answer->soa);   break;
    case RR_NAPTR: rc = encode_rr_naptr(data,&answer->naptr); break;
    case RR_AAAA:  rc = encode_rr_aaaa (data,&answer->aaaa);  break;
    case RR_SRV:   rc = encode_rr_srv  (data,&answer->srv);   break;
    case RR_WKS:   rc = encode_rr_wks  (data,&answer->wks);   break;
    case RR_GPOS:  rc = encode_rr_gpos (data,&answer->gpos);  break;
    case RR_LOC:   rc = encode_rr_loc  (data,&answer->loc);   break;
    case RR_OPT:   rc = encode_rr_opt  (data,&answer->opt);   break;
    
    /*---------------------------------------------------------------------
    ; The following record types all share the same structure (although the
    ; last field name is different, depending upon the record), so they can
    ; share the same call site.  It's enough to shave some space in the
    ; executable while being a cheap and non-obscure size optimization, or
    ; a gross hack, depending upon your view.
    ;----------------------------------------------------------------------*/
    
    case RR_PX:
    case RR_RP:
    case RR_MINFO: rc = encode_rr_minfo(data,&answer->minfo); break;
    
    case RR_AFSDB:
    case RR_RT:
    case RR_MX: rc = encode_rr_mx(data,&answer->mx); break;
    
    case RR_NSAP:
    case RR_ISDN:
    case RR_HINFO: rc = encode_rr_hinfo(data,&answer->hinfo); break;
    
    case RR_X25:
    case RR_SPF:
    case RR_TXT: rc = encode_rr_txt(data,&answer->txt); break;
    
    case RR_NSAP_PTR:
    case RR_MD:
    case RR_MF:
    case RR_MB:
    case RR_MG:
    case RR_MR:
    case RR_NS:
    case RR_PTR:
    case RR_CNAME: rc = encode_domain(data,answer->cname.cname); break;
    
    case RR_NULL: rc = encode_rr_x(data,&answer->x); break;
    
    default: rc = RCODE_NOT_IMPLEMENTED; break;
  }
  
  if (rc != RCODE_OKAY)
    return rc;
    
  /*-----------------------------------------------------
  ; now write the length of the data we've just written
  ;-------------------------------------------------------*/
  
  write_uint16(&(block__s) { .ptr = prdlen , .size = 2 },(uint16_t)(data->packet.ptr - pdata));
  return rc;
}

/***********************************************************************/

dns_rcode_t dns_encode(dns_packet_t *dest,size_t *plen,dns_query_t const *query)
{
  struct idns_header *header;
  uint8_t            *buffer;
  edns_context        data;
  dns_rcode_t         rc;
  
  assert(dest  != NULL);
  assert(plen  != NULL);
  assert(*plen >= sizeof(struct idns_header));
  assert(query_okay(query));
  
  memset(dest,0,*plen);
  
  buffer = (uint8_t *)dest;
  header = (struct idns_header *)buffer;
  
  header->id      = htons(query->id);
  header->opcode  = (query->opcode & 0x0F) << 3;
  header->rcode   = (query->rcode  & 0x0F);
  header->qdcount = htons(query->qdcount);
  header->ancount = htons(query->ancount);
  header->nscount = htons(query->nscount);
  header->arcount = htons(query->arcount);
  
  /*-----------------------------------------------------------------------
  ; I'm not bothering with symbolic constants for the flags; they're only
  ; used in two places in the code (the other being dns_decode()) and
  ; they're not going to change.  It's also obvious from the context what
  ; they're refering to.
  ;-----------------------------------------------------------------------*/
  
  if (!query->query) header->opcode |= 0x80;
  if (query->aa)     header->opcode |= 0x04;
  if (query->tc)     header->opcode |= 0x02;
  if (query->rd)     header->opcode |= 0x01;
  if (query->ra)     header->rcode  |= 0x80;
  if (query->z)      header->rcode  |= 0x40;
  if (query->ad)     header->rcode  |= 0x20;
  if (query->cd)     header->rcode  |= 0x10;
  
  data.packet.size  = *plen - sizeof(struct idns_header);
  data.packet.ptr   = &buffer[sizeof(struct idns_header)];
  data.base         = buffer;
  data.segments.idx = 0;
  data.rropt        = false;
  data.rcode        = query->rcode;
  
  for (size_t i = 0 ; i < query->qdcount ; i++)
  {
    rc = encode_question(&data,&query->questions[i]);
    if (rc != RCODE_OKAY)
      return rc;
  }
  
  for (size_t i = 0 ; i < query->ancount ; i++)
  {
    rc = encode_answer(&data,&query->answers[i]);
    if (rc != RCODE_OKAY)
      return rc;
  }
  
  for (size_t i = 0 ; i < query->nscount ; i++)
  {
    rc = encode_answer(&data,&query->nameservers[i]);
    if (rc != RCODE_OKAY)
      return rc;
  }
  
  /*---------------------------------------------------------------------
  ; RR OPT can only appear once, and only in the additional info section.
  ; Check that we haven't encoded one before.
  ;----------------------------------------------------------------------*/
  
  if (data.rropt)
    return RCODE_FORMAT_ERROR;
    
  for (size_t i = 0 ; i < query->arcount ; i++)
    if ((rc = encode_answer(&data,&query->additional[i])) != RCODE_OKAY)
      return rc;
      
  *plen = (size_t)(data.packet.ptr - buffer);
  return RCODE_OKAY;
}

/*************************************************************************
*
* Memory allocations are done quickly.  The dns_decode() routine is given a
* block of memory to carve allocations out of (4k appears to be good eough;
* 8k is more than enough for UDP packets) and there's no real intelligence
* here---just a quick scheme.  String information is just allocated starting
* at the next available location (referenced in context->dest) whereas the
* few structures that do need allocating require the free pointer to be
* adjusted to a proper memory alignment.  If you need alignments, call
* alloc_struct(), otherwise for strings, use context->dest directly.  You
* *can* use align_memory() directly, just be sure you know what you are
* doing.
*
******************************************************************************/

static bool align_memory(block__s *pool)
{
  size_t newsize;
  size_t delta;
  
  assert(pblock_okay(pool));
  
  if (pool->size < MEM_ALIGN)
    return false;
    
  newsize = pool->size & MEM_MASK;
  if (newsize == pool->size)
    return true;
    
  assert(newsize < pool->size);
  delta = (newsize + MEM_ALIGN) - pool->size;
  assert(delta < pool->size);
  
  pool->ptr  += delta;
  pool->size -= delta;
  
  return true;
}

/*************************************************************************/

static void *alloc_struct(block__s *pool,size_t size)
{
  uint8_t *ptr;
  
  assert(pblock_okay(pool));
  
  if (pool->size == 0)      return NULL;
  if (!align_memory(pool))  return NULL;
  if (pool->size < size)    return NULL;
  
  ptr         = pool->ptr;
  pool->ptr  += size;
  pool->size -= size;
  return (void *)ptr;
}

/***********************************************************************/

static inline uint16_t read_uint16(block__s *parse)
{
  uint16_t val;
  
  /*------------------------------------------------------------------------
  ; caller is reponsible for making sure there's at least two bytes to read
  ;------------------------------------------------------------------------*/
  
  assert(pblock_okay(parse));
  assert(parse->size >= 2);
  
  val = (parse->ptr[0] << 8)
      | (parse->ptr[1]     );
  parse->ptr  += 2;
  parse->size -= 2;
  return val;
}

/********************************************************************/

static inline uint32_t read_uint32(block__s *parse)
{
  uint32_t val;
  
  /*------------------------------------------------------------------------
  ; caller is reponsible for making sure there's at least four bytes to read
  ;------------------------------------------------------------------------*/
  
  assert(pblock_okay(parse));
  assert(parse->size >= 4);
  
  val = (parse->ptr[0] << 24)
      | (parse->ptr[1] << 16)
      | (parse->ptr[2] <<  8)
      | (parse->ptr[3]      );
  parse->ptr  += 4;
  parse->size -= 4;
  return val;
}

/********************************************************************/

static dns_rcode_t read_raw(
        ddns_context  *data,
        uint8_t      **result,
        size_t         len
)
{
  assert(dcontext_okay(data));
  assert(result != NULL);
  
  if (len > 0)
  {
    if (len > data->parse.size)
      return RCODE_FORMAT_ERROR;
      
    /*--------------------------------------------------------------------
    ; Called when we don't know the contents of the data; it's aligned so
    ; that if the data is actually structured, it can probably be read
    ; directly by the clients of this code.
    ;--------------------------------------------------------------------*/
    
    if (!align_memory(&data->dest))
      return RCODE_NO_MEMORY;
      
    if (len > data->dest.size)
      return RCODE_NO_MEMORY;
      
    *result = data->dest.ptr;
    memcpy(data->dest.ptr,data->parse.ptr,len);
    data->parse.ptr  += len;
    data->parse.size -= len;
    data->dest.ptr   += len;
    data->dest.size  -= len;
  }
  else
    *result = NULL;
    
  return RCODE_OKAY;
}

/********************************************************************/

static dns_rcode_t read_string(
        ddns_context  *data,
        const char   **result
)
{
  size_t len;
  
  assert(dcontext_okay(data));
  assert(result != NULL);
  
  len = *data->parse.ptr;
  
  if (data->dest.size < len + 1) /* adjust for NUL byte */
    return RCODE_NO_MEMORY;
    
  if (data->parse.size < len + 1) /* adjust for length byte */
    return RCODE_FORMAT_ERROR;
    
  *result = (char *)data->dest.ptr;
  memcpy(data->dest.ptr,&data->parse.ptr[1],len);
  
  data->parse.ptr  += (len + 1);
  data->parse.size -= (len + 1);
  data->dest.ptr   += len;
  data->dest.size  -= len;
  *data->dest.ptr++ = '\0';
  data->dest.size--;
  
  return RCODE_OKAY;
}

/********************************************************************/

static dns_rcode_t read_domain(
        ddns_context  *data,
        const char   **result
)
{
  block__s *parse = &data->parse;
  block__s  tmp;
  size_t    len;
  int       loop;        /* loop detection */
  
  assert(dcontext_okay(data));
  assert(result != NULL);
  
  *result = (char *)data->dest.ptr;
  loop    = 0;
  
  do
  {
    /*----------------------------
    ; read in a domain segment
    ;-----------------------------*/
    
    if (*parse->ptr < 64)
    {
      len = *parse->ptr;
      
      if (parse->size < len + 1)
        return RCODE_FORMAT_ERROR;
        
      if (data->dest.size < len + 1)
        return RCODE_NO_MEMORY;
        
      if (len)
      {
        memcpy(data->dest.ptr,&parse->ptr[1],len);
        parse->ptr         += (len + 1);
        parse->size        -= (len + 1);
      }
      
      data->dest.size   -= (len + 1);
      data->dest.ptr    += len;
      *data->dest.ptr++  = '.';
    }
    
    /*------------------------------------------
    ; compressed segment---follow the pointer
    ;------------------------------------------*/
    
    else if (*parse->ptr >= 192)
    {
      if (++loop == 256)
        return RCODE_FORMAT_ERROR;
        
      if (parse->size < 2)
        return RCODE_FORMAT_ERROR;
        
      len = read_uint16(parse) & 0x3FFF;
      
      if (len >= data->packet.size)
        return RCODE_FORMAT_ERROR;
        
      tmp.ptr = &data->packet.ptr[len];
      tmp.size = data->packet.size - (size_t)(tmp.ptr - data->packet.ptr);
      parse    = &tmp;
    }
    
    /*-----------------------------------------------------------------------
    ; EDNS0 extended labeles, RFC-2671; the only extension proposed so far,
    ; RFC-2673, was changed from Proposed to Experimental in RFC-3363, so
    ; I'm not including support for it at this time.
    ;-----------------------------------------------------------------------*/
    
    else if ((*parse->ptr >= 64) && (*parse->ptr <= 127))
      return RCODE_FORMAT_ERROR;
      
    /*------------------------------------
    ; reserved for future developments
    ;------------------------------------*/
    
    else
      return RCODE_FORMAT_ERROR;
  } while(*parse->ptr);
  
  parse->ptr++;
  parse->size--;
  *data->dest.ptr++ = '\0';
  data->dest.size--;
  
  return RCODE_OKAY;
}

/********************************************************************/

static inline dns_rcode_t decode_edns0rr_nsid(
        ddns_context *data,
        edns0_opt_t  *opt
)
{
  static char const hexdigits[] = "0123456789ABCDEF";
  
  if (opt->len % 2 == 1)
    return RCODE_FORMAT_ERROR;
    
  if (data->dest.size < opt->len / 2)
    return RCODE_NO_MEMORY;
    
  for (size_t i = 0 ; i < opt->len ; i += 2)
  {
    char const *phexh;
    char const *phexl;
    
    if (!isxdigit(data->parse.ptr[i]))   return RCODE_FORMAT_ERROR;
    if (!isxdigit(data->parse.ptr[i+1])) return RCODE_FORMAT_ERROR;
    
    phexh = memchr(hexdigits,toupper(data->parse.ptr[i])  ,16);
    phexl = memchr(hexdigits,toupper(data->parse.ptr[i+1]),16);
    
    /*------------------------------------------------------------------
    ; phexh and phexl should not be NULL, unless isxdigit() is buggy, and
    ; that is something I'm not assuming.
    ;--------------------------------------------------------------------*/
    
    assert(phexh != NULL);
    assert(phexl != NULL);
    
    *data->dest.ptr = ((phexh - hexdigits) << 4)
                    | ((phexl - hexdigits)     );
    data->dest.ptr++;
    data->dest.size--;
  }
  
  data->parse.ptr  += opt->len;
  data->parse.size -= opt->len;
  opt->len         /= 2;
  return RCODE_OKAY;
}

/***********************************************************************/

static inline dns_rcode_t decode_edns0rr_raw(
        ddns_context *data,
        edns0_opt_t  *opt
)
{
  if (data->dest.size < opt->len)
    return RCODE_NO_MEMORY;
    
  memcpy(data->dest.ptr,data->parse.ptr,opt->len);
  data->parse.ptr  += opt->len;
  data->parse.size -= opt->len;
  data->dest.ptr   += opt->len;
  data->dest.size  -= opt->len;
  return RCODE_OKAY;
}

/*************************************************************/

static dns_rcode_t decode_question(
        ddns_context   *data,
        dns_question_t *pquest
)
{
  dns_rcode_t rc;
  
  assert(dcontext_okay(data));
  assert(pquest != NULL);
  
  rc = read_domain(data,&pquest->name);
  if (rc != RCODE_OKAY)
    return rc;
    
  if (data->parse.size < 4)
    return RCODE_FORMAT_ERROR;
    
  pquest->type  = (dns_type_t) read_uint16(&data->parse);
  pquest->class = (dns_class_t)read_uint16(&data->parse);
  
  /*-------------------------------------------------------
  ; OPT RRs can never be the target of a question as it's
  ; more of a pseudo RR than a real live boy, um, RR.
  ;--------------------------------------------------------*/
  
  if (pquest->type == RR_OPT)
    return RCODE_FORMAT_ERROR;
    
  return RCODE_OKAY;
}

/************************************************************************/

static inline dns_rcode_t decode_rr_soa(
        ddns_context *data,
        dns_soa_t    *psoa,
        size_t        len
)
{
  dns_rcode_t rc;
  
  assert(dcontext_okay(data));
  assert(psoa != NULL);
  
  rc = read_domain(data,&psoa->mname);
  if (rc != RCODE_OKAY) return rc;
  rc = read_domain(data,&psoa->rname);
  if (rc != RCODE_OKAY) return rc;
  
  if (len < 20)
    return RCODE_FORMAT_ERROR;
    
  psoa->serial  = read_uint32(&data->parse);
  psoa->refresh = read_uint32(&data->parse);
  psoa->retry   = read_uint32(&data->parse);
  psoa->expire  = read_uint32(&data->parse);
  psoa->minimum = read_uint32(&data->parse);
  
  return RCODE_OKAY;
}

/***********************************************************************/

static inline dns_rcode_t decode_rr_a(
        ddns_context *data,
        dns_a_t      *pa,
        size_t        len
)
{
  assert(dcontext_okay(data));
  assert(pa != NULL);
  
  if (len != 4) return RCODE_FORMAT_ERROR;
  memcpy(&pa->address,data->parse.ptr,4);
  data->parse.ptr  += 4;
  data->parse.size -= 4;
  return RCODE_OKAY;
}

/***********************************************************************/

static inline dns_rcode_t decode_rr_aaaa(
        ddns_context *data,
        dns_aaaa_t   *pa,
        size_t        len
)
{
  assert(dcontext_okay(data));
  assert(pa != NULL);
  
  if (len != 16) return RCODE_FORMAT_ERROR;
  memcpy(pa->address.s6_addr,data->parse.ptr,16);
  data->parse.ptr  += 16;
  data->parse.size -= 16;
  return RCODE_OKAY;
}

/**********************************************************************/

static inline dns_rcode_t decode_rr_wks(
        ddns_context *data,
        dns_wks_t    *pwks,
        size_t        len
)
{
  assert(dcontext_okay(data));
  assert(pwks != NULL);
  
  if (len < 6) return RCODE_FORMAT_ERROR;
  
  memcpy(&pwks->address,data->parse.ptr,4);
  data->parse.ptr  += 4;
  data->parse.size -= 4;
  pwks->protocol = read_uint16(&data->parse);
  
  pwks->numbits = len - 6;
  return read_raw(data,&pwks->bits,pwks->numbits);
}

/*********************************************************************/

static inline dns_rcode_t decode_rr_mx(
        ddns_context *data,
        dns_mx_t     *pmx,
        size_t        len
)
{
  assert(dcontext_okay(data));
  assert(pmx != NULL);
  
  if (len < 4) return RCODE_FORMAT_ERROR;
  
  pmx->preference = read_uint16(&data->parse);
  return read_domain(data,&pmx->exchange);
}

/**********************************************************************/

static inline dns_rcode_t decode_rr_txt(
        ddns_context *data,
        dns_txt_t    *ptxt,
        size_t        len
)
{
  block__s tmp;
  size_t   worklen;
  size_t   items;
  size_t   slen;
  
  assert(dcontext_okay(data));
  assert(ptxt != NULL);
  
  /*--------------------------------------------------------------------
  ; collapse multiple strings (which are allowed per the spec) into one
  ; large string.  Cache the length as well, as some records might prefer
  ; the length to be there (in case of binary data)
  ;---------------------------------------------------------------------*/
  
  tmp       = data->parse;
  worklen   = len;
  ptxt->len = 0;
  
  for (items = 0 ; worklen ; )
  {
    slen = *tmp.ptr + 1;
    
    if (tmp.size < slen)
      return RCODE_FORMAT_ERROR;
      
    items++;
    ptxt->len += slen - 1;
    tmp.ptr   += slen;
    tmp.size  -= slen;
    worklen   -= slen;
  }
  
  ptxt->text = (char const *)data->dest.ptr;
  
  for (size_t i = 0 ; i < items ; i++)
  {
    slen = *data->parse.ptr;
    
    if (data->dest.size < slen)
      return RCODE_NO_MEMORY;
      
    memcpy(data->dest.ptr,&data->parse.ptr[1],slen);
    data->dest.ptr   += slen;
    data->dest.size  -= slen;
    data->parse.ptr  += (slen + 1);
    data->parse.size -= (slen + 1);
    
    if (data->dest.size == 0)
      return RCODE_NO_MEMORY;
      
    /*--------------------------------------------------------------------
    ; Add space between strings when concatenating them.  If this is the
    ; last string (or the only string), then this space will be overwritten
    ; by the NUL byte.  No wasted memory here.
    ;---------------------------------------------------------------------*/
    
    *data->dest.ptr++ = ' ';
    data->dest.size--;
  }
  
  data->dest.ptr[-1] = '\0';
  return RCODE_OKAY;
}

/**********************************************************************/

static inline dns_rcode_t decode_rr_hinfo(
        ddns_context *data,
        dns_hinfo_t  *phinfo
)
{
  dns_rcode_t rc;
  
  assert(dcontext_okay(data));
  assert(phinfo != NULL);
  
  rc = read_string(data,&phinfo->cpu);
  if (rc != RCODE_OKAY) return rc;
  rc = read_string(data,&phinfo->os);
  return rc;
}

/**********************************************************************/

static inline dns_rcode_t decode_rr_srv(
        ddns_context *data,
        dns_srv_t    *psrv,
        size_t        len
)
{
  assert(dcontext_okay(data));
  assert(psrv != NULL);
  
  if (len < 7)
    return RCODE_FORMAT_ERROR;
    
  psrv->priority = read_uint16(&data->parse);
  psrv->weight   = read_uint16(&data->parse);
  psrv->port     = read_uint16(&data->parse);
  return read_domain(data,&psrv->target);
}

/**********************************************************************/

static inline dns_rcode_t decode_rr_naptr(
        ddns_context *data,
        dns_naptr_t  *pnaptr,
        size_t        len
)
{
  dns_rcode_t rc;
  
  assert(dcontext_okay(data));
  assert(pnaptr != NULL);
  
  if (len < 4)
    return RCODE_FORMAT_ERROR;
    
  pnaptr->order      = read_uint16(&data->parse);
  pnaptr->preference = read_uint16(&data->parse);
  
  rc = read_string(data,&pnaptr->flags);
  if (rc != RCODE_OKAY) return rc;
  rc = read_string(data,&pnaptr->services);
  if (rc != RCODE_OKAY) return rc;
  rc = read_string(data,&pnaptr->regexp);
  if (rc != RCODE_OKAY) return rc;
  return read_domain(data,&pnaptr->replacement);
}

/********************************************************************/

static inline dns_rcode_t decode_rr_sig(
        ddns_context *data,
        dns_sig_t    *psig,
        size_t        len
)
{
  uint8_t     *start;
  size_t       sofar;
  dns_rcode_t  rc;
  
  assert(dcontext_okay(data));
  assert(psig != NULL);
  
  if (len < 18)
    return RCODE_FORMAT_ERROR;
    
  /*-----------------------------------------------------------------------
  ; The signature portion doesn't have a length code.  Because of that, we
  ; need to track how much data is left so we can pull it out.  We record
  ; the start of the parsing area, and once we get past the signer, we can
  ; calculate the remainder data to pull out.
  ;------------------------------------------------------------------------*/
  
  start = data->parse.ptr;
  
  psig->covered      = read_uint16(&data->parse);
  psig->algorithm    = *data->parse.ptr++; data->parse.size--;
  psig->labels       = *data->parse.ptr++; data->parse.size--;
  psig->originttl    = read_uint32(&data->parse);
  psig->sigexpire    = read_uint32(&data->parse);
  psig->timesigned   = read_uint32(&data->parse);
  psig->keyfootprint = read_uint16(&data->parse);
  
  rc = read_domain(data,&psig->signer);
  if (rc != RCODE_OKAY) return rc;
  
  sofar = (size_t)(data->parse.ptr - start);
  if (sofar > len) return RCODE_FORMAT_ERROR;
  
  psig->sigsize = len - sofar;
  return read_raw(data,&psig->signature,psig->sigsize);
}

/******************************************************************/

static inline dns_rcode_t decode_rr_minfo(
                ddns_context *data,
                dns_minfo_t  *pminfo
)
{
  dns_rcode_t rc;
  
  assert(dcontext_okay(data));
  assert(pminfo != NULL);
  
  rc = read_domain(data,&pminfo->rmailbx);
  if (rc != RCODE_OKAY) return rc;
  return read_domain(data,&pminfo->emailbx);
}

/*****************************************************************/

static dns_rcode_t dloc_double(
                ddns_context *data,
                double       *pvalue
)
{
  size_t len;
  
  assert(dcontext_okay(data));
  assert(pvalue != NULL);
  
  len = *data->parse.ptr;
  if (len > data->parse.size - 1)
    return RCODE_FORMAT_ERROR;
    
  char buffer[len + 1];
  memcpy(buffer,&data->parse.ptr[1],len);
  buffer[len++] = '\0';
  
  data->parse.ptr += len;
  data->parse.size -= len;
  
  errno = 0;
  *pvalue = strtod(buffer,NULL);
  if (errno) return RCODE_FORMAT_ERROR;
  
  return RCODE_OKAY;
}

/****************************************************************/

static void dgpos_angle(
        dnsgpos_angle *pa,
        double         v
)
{
  double ip;
  
  v = modf(v,&ip) *   60.0; pa->deg = ip;
  v = modf(v,&ip) *   60.0; pa->min = ip;
  v = modf(v,&ip) * 1000.0; pa->sec = ip;
  pa->frac = v;
}

/*****************************************************************/

static inline dns_rcode_t decode_rr_gpos(
                ddns_context *data,
                dns_gpos_t   *pgpos
)
{
  dns_rcode_t rc;
  double      lat;
  double      lng;
  
  assert(dcontext_okay(data));
  assert(pgpos != NULL);
  
  rc = dloc_double(data,&lng);
  if (rc != RCODE_OKAY) return rc;
  rc = dloc_double(data,&lat);
  if (rc != RCODE_OKAY) return rc;
  
  if (lng < 0.0)
  {
    pgpos->longitude.nw = true;
    lng                 = fabs(lng);
  }
  
  if (lat >= 0.0)
    pgpos->latitude.nw = true;
  else
    lat = fabs(lat);
    
  dgpos_angle(&pgpos->longitude,lng);
  dgpos_angle(&pgpos->latitude, lat);
  
  return dloc_double(data,&pgpos->altitude);
}

/**************************************************************************
*
* You really, no, I mean it, *REALLY* need to read RFC-1876 to understand
* all the crap that's going on for deciphering RR_LOC.
*
**************************************************************************/

static int dloc_scale(
        unsigned long long *presult,
        const int           scale
)
{
  int spow;
  int smul;
  
  assert(presult != NULL);
  
  smul = scale >> 4;
  spow = scale & 0x0F;
  
  if ((spow > 9) || (smul > 9))
    return RCODE_FORMAT_ERROR;
    
  *presult = (unsigned long)(pow(10.0,spow) * smul);
  return RCODE_OKAY;
}

/**************************************************************/

static void dloc_angle(
        dnsgpos_angle *pa,
        const long     v
)
{
  ldiv_t partial;
  
  assert(pa != NULL);
  
  partial  = ldiv(v,1000L);
  pa->frac = partial.rem;
  partial  = ldiv(partial.quot,60L);
  pa->sec  = partial.rem;
  partial  = ldiv(partial.quot,60L);
  pa->min  = partial.rem;
  pa->deg  = partial.quot;
}

/*************************************************************/

static inline dns_rcode_t decode_rr_loc(
                ddns_context *data,
                dns_loc_t    *ploc,
                size_t        len
)
{
  dns_rcode_t    rc;
  unsigned long  lat;
  unsigned long  lng;
  
  assert(dcontext_okay(data));
  assert(ploc != NULL);
  
  if (len < 16) return RCODE_FORMAT_ERROR;
  
  ploc->version = data->parse.ptr[0];
  
  if (ploc->version != 0)
    return RCODE_FORMAT_ERROR;
    
  rc = dloc_scale(&ploc->size,data->parse.ptr[1]);
  if (rc != RCODE_OKAY) return rc;
  rc = dloc_scale(&ploc->horiz_pre,data->parse.ptr[2]);
  if (rc != RCODE_OKAY) return rc;
  rc = dloc_scale(&ploc->vert_pre,data->parse.ptr[3]);
  if (rc != RCODE_OKAY) return rc;
  
  data->parse.ptr += 4;
  
  lat            = read_uint32(&data->parse);
  lng            = read_uint32(&data->parse);
  ploc->altitude = read_uint32(&data->parse) - LOC_ALT_BIAS;
  
  if (lat >= LOC_BIAS)  /* north */
  {
    ploc->latitude.nw = true;
    lat -= LOC_BIAS;
  }
  else
    lat = LOC_BIAS - lat;
    
  if (lng >= LOC_BIAS)  /* east */
    lng -= LOC_BIAS;
  else
  {
    ploc->longitude.nw = true;
    lng = LOC_BIAS - lng;
  }
  
  if (lat > LOC_LAT_MAX)
    return RCODE_FORMAT_ERROR;
    
  if (lng > LOC_LNG_MAX)
    return RCODE_FORMAT_ERROR;
    
  dloc_angle(&ploc->latitude ,lat);
  dloc_angle(&ploc->longitude,lng);
  
  return RCODE_OKAY;
}

/***************************************************************/

static inline dns_rcode_t decode_rr_opt(
                ddns_context   *data,
                dns_edns0opt_t *opt,
                size_t          len
)
{
  assert(data != NULL);
  assert(opt  != NULL);
  
  if (data->edns) /* there can be only one */
    return RCODE_FORMAT_ERROR;
    
  data->edns   = true;
  opt->numopts = 0;
  opt->opts    = NULL;
  
  if (len)
  {
    uint8_t *scan;
    size_t   length;
    
    assert(dcontext_okay(data));
    assert(len > 4);
    
    for (scan = data->parse.ptr , opt->numopts = 0 , length = len ; length > 0 ; )
    {
      size_t size;
      
      opt->numopts++;
      size    = ((scan[2] << 8) | (scan[3])) + 4;
      scan   += size;
      
      if (size > length)
        return RCODE_FORMAT_ERROR;
        
      length -= size;
    }
    
    opt->opts = alloc_struct(&data->dest,sizeof(edns0_opt_t) * opt->numopts);
    if (opt->opts == NULL)
      return RCODE_NO_MEMORY;
      
    for (size_t i = 0 ; i < opt->numopts ; i++)
    {
      dns_rcode_t rc;
      
      opt->opts[i].code = read_uint16(&data->parse);
      opt->opts[i].len  = read_uint16(&data->parse);
      
      /*-----------------------------------------------------------------
      ; much like in read_raw(), we don't necessarily know the data we're
      ; reading, so why not align it?
      ;------------------------------------------------------------------*/
      
      if (!align_memory(&data->dest))
        return RCODE_NO_MEMORY;
        
      opt->opts[i].data = data->dest.ptr;
      
      switch(opt->opts[i].code)
      {
        case EDNS0RR_NSID: rc = decode_edns0rr_nsid(data,&opt->opts[i]); break;
        default:           rc = decode_edns0rr_raw (data,&opt->opts[i]); break;
      }
      
      if (rc != RCODE_OKAY) return rc;
    }
  }
  
  return RCODE_OKAY;
}

/**********************************************************************/

static dns_rcode_t decode_answer(
                ddns_context *data,
                dns_answer_t *pans
)
{
  size_t      len;
  size_t      rest;
  dns_rcode_t rc;
  
  assert(dcontext_okay(data));
  assert(pans != NULL);
  
  rc = read_domain(data,&pans->generic.name);
  if (rc != RCODE_OKAY)
    return rc;
    
  if (data->parse.size < 10)
    return RCODE_FORMAT_ERROR;
    
  pans->generic.type = read_uint16(&data->parse);
  
  /*-----------------------------------------------------------------
  ; RR_OPT is annoying, since the defined class and ttl fields are
  ; interpreted completely differently.  Thanks a lot, Paul Vixie!  So we
  ; need to special case this stuff a bit.
  ;----------------------------------------------------------------*/
  
  if (pans->generic.type == RR_OPT)
  {
    pans->generic.class   = CLASS_UNKNOWN;
    pans->generic.ttl     = 0;
    pans->opt.udp_payload = read_uint16(&data->parse);
    data->response->rcode = (data->parse.ptr[0] << 4) | data->response->rcode;
    
    if (data->parse.ptr[1] != 0)        /* version */
      return RCODE_FORMAT_ERROR;
      
    /*--------------------------------------------------------------------
    ; RFC-3225 states that of octets 2 and 3, only the left-most bit
    ; of byte 2 is defined (the DO bit)---the rest are supposed to be
    ; 0.  But of *course* Google is using these bits for their own
    ; "don't be evil" purposes, whatever that might be.
    ;
    ; Thanks Google.  Thanks for being like Microsoft---embrace, extend and
    ; then extinquish.  Way to be not evil!
    ;---------------------------------------------------------------------*/
    
    data->parse.ptr  += 2;
    data->parse.size -= 2;
    
    pans->opt.fug = read_uint16(&data->parse);
    pans->opt.fdo = pans->opt.fug > 0x7FFF;
    pans->opt.fug &= 0x7FFF;
  }
  else
  {
    pans->generic.class = read_uint16(&data->parse);
    pans->generic.ttl   = read_uint32(&data->parse);
  }
  
  len  = read_uint16(&data->parse);
  rest = data->packet.size - (data->parse.ptr - data->packet.ptr);
  
  if (len > rest)
    return RCODE_FORMAT_ERROR;
    
  switch(pans->generic.type)
  {
    case RR_A:     return decode_rr_a    (data,&pans->a    ,len);
    case RR_SOA:   return decode_rr_soa  (data,&pans->soa  ,len);
    case RR_NAPTR: return decode_rr_naptr(data,&pans->naptr,len);
    case RR_AAAA:  return decode_rr_aaaa (data,&pans->aaaa ,len);
    case RR_SRV:   return decode_rr_srv  (data,&pans->srv  ,len);
    case RR_WKS:   return decode_rr_wks  (data,&pans->wks  ,len);
    case RR_GPOS:  return decode_rr_gpos (data,&pans->gpos);
    case RR_LOC:   return decode_rr_loc  (data,&pans->loc  ,len);
    case RR_OPT:   return decode_rr_opt  (data,&pans->opt  ,len);
    
    /*----------------------------------------------------------------------
    ; The following record types all share the same structure (although the
    ; last field name is different, depending upon the record), so they can
    ; share the same call site.  It's enough to shave some space in the
    ; executable while being a cheap and non-obscure size optimization, or
    ; a gross hack, depending upon your view.
    ;----------------------------------------------------------------------*/
    
    case RR_PX:
    case RR_RP:
    case RR_MINFO: return decode_rr_minfo(data,&pans->minfo);
    
    case RR_AFSDB:
    case RR_RT:
    case RR_MX: return decode_rr_mx(data,&pans->mx,len);
    
    case RR_NSAP:
    case RR_ISDN:
    case RR_HINFO: return decode_rr_hinfo(data,&pans->hinfo);
    
    case RR_X25:
    case RR_SPF:
    case RR_TXT: return decode_rr_txt(data,&pans->txt,len);
    
    case RR_NSAP_PTR:
    case RR_MD:
    case RR_MF:
    case RR_MB:
    case RR_MG:
    case RR_MR:
    case RR_NS:
    case RR_PTR:
    case RR_CNAME: return read_domain(data,&pans->cname.cname);
    
    case RR_NULL:
    default:
         pans->x.size = len;
         return read_raw(data,&pans->x.rawdata,len);
  }
  
  assert(0);
  return RCODE_OKAY;
}

/***********************************************************************/

dns_rcode_t dns_decode(dns_decoded_t *presponse,size_t *prsize,dns_packet_t const *buffer,size_t len)
{
  struct idns_header const *header;
  dns_query_t              *response;
  ddns_context              context;
  dns_rcode_t               rc;
  
  assert(presponse != NULL);
  assert(prsize    != NULL);
  assert(*prsize   >= sizeof(dns_query_t));
  assert(buffer    != NULL);
  assert(len       >= sizeof(struct idns_header));
  
  context.packet.ptr  = (uint8_t *)buffer;
  context.packet.size = len;
  context.parse.ptr   = &context.packet.ptr[sizeof(struct idns_header)];
  context.parse.size  = len - sizeof(struct idns_header);
  context.dest.ptr    = (uint8_t *)presponse;
  context.dest.size   = *prsize;
  context.edns        = false;
  
  /*--------------------------------------------------------------------------
  ; we use the block of data given to store the results.  context.dest
  ; contains this block and allocations are doled out from this.  This odd
  ; bit here sets the structure to the start of the block we're using, and
  ; then "allocates" the size f the structure in the context variable.  I do
  ; this as a test of the allocation routines when the address is already
  ; aligned (an assumption I'm making)---the calls to assert() ensure this
  ; behavior.
  ;--------------------------------------------------------------------------*/
  
  response         = (dns_query_t *)context.dest.ptr;
  context.response = alloc_struct(&context.dest,sizeof(dns_query_t));
  
  assert(context.response != NULL);
  assert(context.response == response);
  
  memset(response,0,sizeof(dns_query_t));
  response->questions   = NULL;
  response->answers     = NULL;
  response->nameservers = NULL;
  response->additional  = NULL;
  
  header = (struct idns_header *)buffer;
  
  response->id      = ntohs(header->id);
  response->opcode  = (header->opcode >> 3) & 0x0F;
  response->query   = (header->opcode & 0x80) != 0x80;
  response->aa      = (header->opcode & 0x04) == 0x04;
  response->tc      = (header->opcode & 0x02) == 0x02;
  response->rd      = (header->opcode & 0x01) == 0x01;
  response->ra      = (header->rcode  & 0x80) == 0x80;
  response->z       = (header->rcode  & 0x40) == 0x40;
  response->ad      = (header->rcode  & 0x20) == 0x20;
  response->cd      = (header->rcode  & 0x10) == 0x10;
  response->rcode   = (header->rcode  & 0x0F);
  response->qdcount = ntohs(header->qdcount);
  response->ancount = ntohs(header->ancount);
  response->nscount = ntohs(header->nscount);
  response->arcount = ntohs(header->arcount);
  
  response->questions   = alloc_struct(&context.dest,response->qdcount * sizeof(dns_question_t));
  response->answers     = alloc_struct(&context.dest,response->ancount * sizeof(dns_answer_t));
  response->nameservers = alloc_struct(&context.dest,response->nscount * sizeof(dns_answer_t));
  response->additional  = alloc_struct(&context.dest,response->arcount * sizeof(dns_answer_t));
  
  if (
          (response->qdcount && (response->questions   == NULL))
       || (response->ancount && (response->answers     == NULL))
       || (response->nscount && (response->nameservers == NULL))
       || (response->arcount && (response->additional  == NULL))
     )
  {
    return RCODE_NO_MEMORY;
  }
  
  for (size_t i = 0 ; i < response->qdcount ; i++)
  {
    rc = decode_question(&context,&response->questions[i]);
    if (rc != RCODE_OKAY)
      return rc;
  }
  
  for (size_t i = 0 ; i < response->ancount ; i++)
  {
    rc = decode_answer(&context,&response->answers[i]);
    if (rc != RCODE_OKAY)
      return rc;
  }
  
  for (size_t i = 0 ; i < response->nscount ; i++)
  {
    rc = decode_answer(&context,&response->nameservers[i]);
    if (rc != RCODE_OKAY)
      return rc;
  }
  
  /*-------------------------------------------------------------
  ; RR OPT can only appear once, and only in the additional info
  ; section.  Check that we haven't seen one before.
  ;-------------------------------------------------------------*/
  
  if (context.edns) return RCODE_FORMAT_ERROR;
  
  for (size_t i = 0 ; i < response->arcount ; i++)
  {
    rc = decode_answer(&context,&response->additional[i]);
    if (rc != RCODE_OKAY)
      return rc;
  }
  
  *prsize = (size_t)(context.dest.ptr - (uint8_t *)presponse);
  return RCODE_OKAY;
}

/************************************************************************/
