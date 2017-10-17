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
*	This function takes a filled in dns_query_t structure (assumed to be
*	filled out correctly and creates the wire representation of that
*	query into a buffer supplied to the routine.
*
*	THIS ROUTINE DOES NOT ALLOCATE MEMORY, NOR DOES IT USE GLOBAL
*	VARAIBLES. IT IS THEREFORE THREAD SAFE.
*
*	See test.c for an example of calling this routine.
*
*  dns_decode()
*
*	This function takes the wire representation of a response, decodes
*	and returns a dns_query_t filled out with the various records.  You
*	supply a block of memory sufficient enough to store the dns_query_t
*	and any various strings/structures used in the dns_query_t (I've
*	found 8K to be more than enough for decoding a UDP response but
*	that's a very conservative value; 4K may be good enough).
*
*	THIS ROUTINE DOES NOT ALLOCATE MEMORY, NOR DOES IT USE GLOBAL
*	VARIABLES.  IT IS THEREFORE THREAD SAFE.
*
*	See test.c for an example of calling this routine.
*
*	This code is written using C99.
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

#define MEM_ALIGN	sizeof(dns_decoded_t)
#define MEM_MASK	~(sizeof(dns_decoded_t) - 1uL)

/************************************************************************/

typedef struct block
{
  size_t   size;
  uint8_t *ptr;
} block_t;

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

typedef struct idns_context
{
  block_t      packet;
  block_t      parse;
  block_t      dest;	/* see comments in align_memory() */
  dns_query_t *response;
  bool         edns;
} idns_context;

/***********************************************************************/

static        dns_rcode_t  dns_encode_domain	(block_t *const restrict,const char           *restrict,      size_t) __attribute__ ((nothrow,nonnull));
static        dns_rcode_t  dns_encode_string	(block_t *const restrict,const char           *restrict,const size_t) __attribute__ ((nothrow,nonnull));
static        dns_rcode_t  dns_encode_question  (block_t *const restrict,const dns_question_t *const restrict)        __attribute__ ((nothrow,nonnull));
static inline dns_rcode_t  encode_edns0rr_nsid	(block_t *const restrict,const edns0_opt_t    *const restrict)        __attribute__ ((nothrow,nonnull));
static inline dns_rcode_t  encode_edns0rr_raw	(block_t *const restrict,const edns0_opt_t    *const restrict)        __attribute__ ((nothrow,nonnull));
static inline dns_rcode_t  encode_rr_opt    	(block_t *const restrict,const dns_query_t    *const restrict,const dns_edns0opt_t *const restrict) __attribute__ ((nothrow,nonnull));
static inline dns_rcode_t  encode_rr_naptr	(block_t *const restrict,const dns_naptr_t    *const restrict)        __attribute__ ((nothrow,nonnull));

static        bool	   align_memory	(block_t *const)		__attribute__ ((nothrow,nonnull,   warn_unused_result));
static        void        *alloc_struct	(block_t *const,const size_t)	__attribute__ ((nothrow,nonnull(1),warn_unused_result,malloc));

static inline void         write_uint16 (block_t *const,uint16_t)                                         __attribute__ ((nothrow,nonnull(1)));
static inline void         write_uint32 (block_t *const,uint32_t)                                         __attribute__ ((nothrow,nonnull(1)));
static inline uint16_t	   read_uint16	(block_t *const)		                                  __attribute__ ((nothrow,nonnull));
static inline uint32_t	   read_uint32	(block_t *const)		                                  __attribute__ ((nothrow,nonnull));
static        dns_rcode_t  read_raw	(idns_context *const restrict,uint8_t    **restrict,const size_t) __attribute__ ((nothrow,nonnull(1,2)));
static        dns_rcode_t  read_string	(idns_context *const restrict,const char **restrict)              __attribute__ ((nothrow,nonnull(1,2)));
static        dns_rcode_t  read_domain	(idns_context *const restrict,const char **restrict)	          __attribute__ ((nothrow,nonnull));

static inline dns_rcode_t  decode_edns0rr_nsid	(idns_context *const restrict,edns0_opt_t *const restrict) __attribute__ ((nothrow,nonnull));
static inline dns_rcode_t  decode_edns0rr_raw	(idns_context *const restrict,edns0_opt_t *const restrict) __attribute__ ((nothrow,nonnull));

static        dns_rcode_t  decode_question(idns_context *const restrict,dns_question_t *const restrict)		     __attribute__ ((nothrow,nonnull));
static inline dns_rcode_t  decode_rr_soa  (idns_context *const restrict,dns_soa_t      *const restrict,const size_t) __attribute__ ((nothrow,nonnull(1,2)));
static inline dns_rcode_t  decode_rr_a	  (idns_context *const restrict,dns_a_t        *const restrict,const size_t) __attribute__ ((nothrow,nonnull(1,2)));
static inline dns_rcode_t  decode_rr_wks  (idns_context *const restrict,dns_wks_t      *const restrict,const size_t) __attribute__ ((nothrow,nonnull(1,2)));
static inline dns_rcode_t  decode_rr_mx	  (idns_context *const restrict,dns_mx_t       *const restrict,const size_t) __attribute__ ((nothrow,nonnull(1,2)));
static inline dns_rcode_t  decode_rr_txt  (idns_context *const restrict,dns_txt_t      *const restrict,const size_t) __attribute__ ((nothrow,nonnull(1,2)));
static inline dns_rcode_t  decode_rr_hinfo(idns_context *const restrict,dns_hinfo_t    *const restrict)              __attribute__ ((nothrow,nonnull(1,2)));
static inline dns_rcode_t  decode_rr_naptr(idns_context *const restrict,dns_naptr_t    *const restrict,const size_t) __attribute__ ((nothrow,nonnull(1,2)));
static inline dns_rcode_t  decode_rr_aaaa (idns_context *const restrict,dns_aaaa_t     *const restrict,const size_t) __attribute__ ((nothrow,nonnull(1,2)));
static inline dns_rcode_t  decode_rr_srv  (idns_context *const restrict,dns_srv_t      *const restrict,const size_t) __attribute__ ((nothrow,nonnull(1,2)));
static inline dns_rcode_t  decode_rr_sig  (idns_context *const restrict,dns_sig_t      *const restrict,const size_t) __attribute__ ((nothrow,nonnull(1,2),unused));
static inline dns_rcode_t  decode_rr_minfo(idns_context *const restrict,dns_minfo_t    *const restrict)              __attribute__ ((nothrow,nonnull(1,2)));
static inline dns_rcode_t  decode_rr_gpos (idns_context *const restrict,dns_gpos_t     *const restrict)              __attribute__ ((nothrow,nonnull(1,2)));
static inline dns_rcode_t  decode_rr_loc  (idns_context *const restrict,dns_loc_t      *const restrict,const size_t) __attribute__ ((nothrow,nonnull(1,2)));
static inline dns_rcode_t  decode_rr_opt  (idns_context *const restrict,dns_edns0opt_t *const restrict,const size_t) __attribute__ ((nothrow,nonnull(1,2)));
static        dns_rcode_t  decode_answer  (idns_context *const restrict,dns_answer_t   *const restrict)              __attribute__ ((nothrow,nonnull(1,2)));

/***********************************************************************/

#ifndef NDEBUG
  static int query_okay  (const dns_query_t *const)  __attribute__ ((unused));
  static int pblock_okay (const block_t *const)      __attribute__ ((unused));
  static int block_okay  (const block_t)             __attribute__ ((unused));
  static int context_okay(const idns_context *const) __attribute__ ((unused));
  
  static int query_okay(const dns_query_t *const query)
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
  
  static int pblock_okay(const block_t *const block)
  {
    assert(block       != NULL);
    assert(block->ptr  != NULL);
    assert(block->size >  0);
    return 1;
  }
  
  static int block_okay(const block_t block)
  {
    assert(block.ptr  != NULL);
    assert(block.size >  0);
    return 1;
  }
  
  static int context_okay(const idns_context *const data)
  {
    assert(data     != NULL);
    assert(data->response != NULL);
    assert(block_okay(data->packet));
    assert(block_okay(data->parse));
    assert(block_okay(data->dest));
    return 1;
  }
#endif

/*******************************************************************/

dns_rcode_t dns_encode(
	dns_packet_t      *const restrict dest,
	size_t            *const restrict plen,
	const dns_query_t *const restrict query
)
{
  struct idns_header *header;
  uint8_t            *buffer;
  block_t             data;
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
  ; used in two places in the code (the other being dns_encode()) and
  ; they're not going to change.  It's also obvious from the context what
  ; they're refering to.
  ;-----------------------------------------------------------------------*/
  
  if (!query->query) header->opcode |= 0x80;
  if (query->aa)     header->opcode |= 0x04;
  if (query->tc)     header->opcode |= 0x02;
  if (query->rd)     header->opcode |= 0x01;
  if (query->ra)     header->rcode  |= 0x80;
  if (query->ad)     header->rcode  |= 0x20;
  if (query->cd)     header->rcode  |= 0x10;
  
  data.size = *plen - sizeof(struct idns_header);
  data.ptr  = &buffer[sizeof(struct idns_header)];
  
  for (size_t i = 0 ; i < query->qdcount ; i++)
  {
    rc = dns_encode_question(&data,&query->questions[i]);
    if (rc != RCODE_OKAY)
      return rc;
  }
  
  /*----------------------------------------------------------------
  ; I need to encode NAPTRs, so that's all we can encode as an
  ; answer for now.  We also support an addtional records for the
  ; EDNS stuff, but that's it for now.
  ;---------------------------------------------------------------*/
  
  for (size_t i = 0 ; i < query->ancount ; i++)
  {
    switch(query->answers[i].generic.type)
    {
      case RR_NAPTR: rc = encode_rr_naptr(&data,&query->answers[i].naptr); break;
      default:       assert(0); rc = RCODE_NOT_IMPLEMENTED; break;
    }
    
    if (rc != RCODE_OKAY)
      return rc;
  }
 
  /*---------------------------------------------
  ; skip name sever records
  ;----------------------------------------------*/
  
  assert(query->nscount == 0);
  
  /*------------------------------------------------------
  ; EDNS only supported additional record type for now
  ;-------------------------------------------------------*/
  
  for (size_t i = 0 ; i < query->arcount ; i++)
  {
    switch(query->additional[i].generic.type)
    {
      case RR_OPT: rc = encode_rr_opt(&data,query,&query->additional[i].opt); break;
      default:     assert(0); rc = RCODE_NOT_IMPLEMENTED; break;
    }
    
    if (rc != RCODE_OKAY)
      return rc;
  }
  
  *plen = (size_t)(data.ptr - buffer);
  return RCODE_OKAY;
}

/*********************************************************************/

static dns_rcode_t dns_encode_domain(
	block_t    *const restrict data,
	const char *restrict       name,
	size_t                     len
)
{
  uint8_t *start;
  uint8_t *end;
  uint8_t *back_ptr;
  
  assert(pblock_okay(data));
  assert(name != NULL);
  assert(len  >  0);
  
  /*------------------------------------------------------------------------
  ; The root domain is ".", which internally is represented by a single NUL
  ; byte.  The normal route through this code will encode the root domain as
  ; two NUL bytes, which is incorrect.  So we special case it.
  ;------------------------------------------------------------------------*/
  
  if (len == 1)
  {
    if (data->size == 0)
      return RCODE_NO_MEMORY;
    
    if (*name != '.')
      return RCODE_NAME_ERROR;
      
    *data->ptr++ = 0;
    data->size--;
    return RCODE_OKAY;
  }
  
  if (name[len - 1] != '.')	/* name must be fully qualified */
    return RCODE_NAME_ERROR;
  
  if (data->size < len + 1)
    return RCODE_NO_MEMORY;

  /*----------------------------------------------------------------------
  ; Okay, here's how this works.  We have a domain name: 
  ;
  ;	lucy.roswell.conman.org.
  ;
  ; We copy it to the destination buffer, but one octet in, because we need
  ; to record the length of each segment:
  ;
  ;	|   |'l'|'u'|'c'|'y'|'.'|'r'|...
  ;
  ; back_ptr will always point to the location to the length octet, whereas
  ; start will point to the start of the segment, and end will always point
  ; to the next '.' character (which is guarenteed by the checks above).
  ;
  ; Okay, so then for our string, we find the next '.':
  ;
  ;	|   |'l'|'u'|'c'|'y'|'.'|'r'|...
  ;       ^   ^               ^
  ;       |   |               \-- end
  ;	  |   \------------------ start
  ;	  \---------------------- back_ptr
  ;
  ; We then calculate the length of the segment, and write that value into
  ; the location at back_ptr:
  ;
  ;	| 4 |'l'|'u'|'c'|'y'|'.'|'r'|...
  ;
  ; We then advance back_ptr to end, set start to the next character and
  ; keep going while we have characters left.  Upon exit from the loop,
  ; back_ptr points to the last '.' in the name, which is then set to '\0'
  ; to designate the root pointer (and thus, the end of the domain name).
  ;
  ; It's because of this algorithm that we had to special case the root
  ; domain designation.  I'll leave that as an exercise to the reader.
  ;--------------------------------------------------------------------*/
  
  memcpy(&data->ptr[1],name,len);
  data->size -= (len + 1);

  back_ptr = data->ptr;
  start    = &data->ptr[1];
  end      = &data->ptr[1];
  
  while(len)
  {
    size_t delta;
    
    end = memchr(start,'.',len);
    assert(end != NULL);	/* must be true---checked above */
    
    delta = (size_t)(end - start);
    assert(delta <= len);
    if (delta > 63)
      return RCODE_NAME_ERROR;
    
    *back_ptr = (uint8_t)delta;
    back_ptr  = end;
    start     = end + 1;
    len       -= (delta + 1);
  }
  
  *back_ptr = 0;
  data->ptr = end + 1;
  
  return RCODE_OKAY;
}

/*******************************************************************/

static dns_rcode_t dns_encode_string(
	block_t      *const restrict data,
	const char   *restrict       text,
	const size_t                 size
)
{
  assert(pblock_okay(data));
  assert(text != NULL);

  if (size > 255)            return RCODE_BAD_STRING;
  if (data->size < size + 1) return RCODE_NO_MEMORY;
  
  *data->ptr++ = size;
  memcpy(data->ptr,text,size);
  data->ptr += size;
  data->size -= (size + 1);
  
  return RCODE_OKAY;
}

/******************************************************************/

static dns_rcode_t dns_encode_question(
	block_t              *const restrict data,
	const dns_question_t *const restrict pquestion
)
{
  int rc;
  
  assert(pblock_okay(data));
  assert(pquestion        != NULL);
  assert(pquestion->name  != NULL);
  assert(pquestion->class >= 1);
  assert(pquestion->class <= 4);
    
  rc = dns_encode_domain(data,pquestion->name,strlen(pquestion->name));
  if (rc != RCODE_OKAY)
    return rc;
  
  if (data->size < 4)
    return RCODE_NO_MEMORY;
  
  write_uint16(data,pquestion->type);
  write_uint16(data,pquestion->class);
  
  return RCODE_OKAY;
}

/*************************************************************************/

static inline dns_rcode_t encode_edns0rr_nsid(
	block_t           *const restrict data,
	const edns0_opt_t *const restrict opt
)
{
  size_t newlen;
  
  assert(pblock_okay(data));
  assert(opt       != NULL);
  assert(opt->code == EDNS0RR_NSID);
  assert(opt->len  <= UINT16_MAX);
  
  /*------------------------------------------------------------------------
  ; RFC-5001 specifies that the data for an NSID RR is the hexstring of the
  ; data, and no other meaning from the strings is to be inferred.  So we
  ; encode the data to save you from doing it.
  ;------------------------------------------------------------------------*/
  
  newlen = opt->len * 2;
  if (data->size < newlen + sizeof(uint16_t) + sizeof(uint16_t))
    return RCODE_NO_MEMORY;
  
  char   buffer[newlen + 1];
  size_t nidx;
  size_t i;
  
  for (i = nidx = 0 ; i < opt->len ; i++ , nidx += 2)
    sprintf(&buffer[nidx],"%02X",opt->data[i]);
  
  assert(newlen == strlen(buffer));
  
  write_uint16(data,opt->code);
  write_uint16(data,newlen);
  memcpy(data->ptr,buffer,newlen);
  data->ptr  += newlen;
  data->size -= newlen;
  return RCODE_OKAY;
}

/**********************************************************************/

static inline dns_rcode_t encode_edns0rr_raw(
	block_t           *const restrict data,
	const edns0_opt_t *const restrict opt
)
{
  assert(pblock_okay(data));
  assert(opt       != NULL);
  assert(opt->code <= UINT16_MAX);
  assert(opt->len  <= UINT16_MAX);
  
  if (data->size < opt->len + sizeof(uint16_t) + sizeof(uint16_t))
    return RCODE_NO_MEMORY;
  
  write_uint16(data,opt->code);
  write_uint16(data,opt->len);
  memcpy(data->ptr,opt->data,opt->len);
  data->ptr  += opt->len;
  data->size -= opt->len;
  return RCODE_OKAY;
}

/*************************************************************************/

static inline dns_rcode_t encode_rr_opt(
	block_t              *const restrict data,
	const dns_query_t    *const restrict query,
	const dns_edns0opt_t *const restrict opt
)
{
  uint8_t *prdlen;
  size_t   rdlen;
  size_t   i;
  
  assert(pblock_okay(data));
  assert(query            != NULL);
  assert(opt              != NULL);
  assert(opt->class       == CLASS_UNKNOWN);
  assert(opt->ttl         == 0);
  assert(opt->version     == 0);
  assert(opt->udp_payload <= UINT16_MAX);
  
  if (data->size < 11)
    return RCODE_NO_MEMORY;

  data->ptr[0] = '\0';	/* root domain */
  data->ptr++;
  data->size--;

  write_uint16(data,RR_OPT);
  write_uint16(data,opt->udp_payload);
  data->ptr[0] = query->rcode >> 4;
  data->ptr[1] = opt->version;
  data->ptr[2] = 0;
  data->ptr[3] = 0;
  
  if (opt->fdo) data->ptr[2] |= 0x80;
    
  data->ptr  += 4;
  data->size -= 4;
  
  /*----------------------------------------------------------------------
  ; save the location for RDLEN, and set it to 0 for now.  After we encode
  ; the rest of the packet, we'll patch this with the correct length.
  ;----------------------------------------------------------------------*/
  
  prdlen = data->ptr;
  write_uint16(data,0);	/* place holder for now */
  
  for (i = 0 ; i < opt->numopts; i++)
  {
    dns_rcode_t rc;
    
    switch(opt->opts[i].code)
    {
      case EDNS0RR_NSID: rc = encode_edns0rr_nsid(data,&opt->opts[i]); break;
      default:           rc = encode_edns0rr_raw (data,&opt->opts[i]); break;
    }
    
    if (rc != RCODE_OKAY) return rc;
  }
  
  rdlen     = (size_t)(data->ptr - prdlen) - sizeof(uint16_t);
  prdlen[0] = (rdlen >> 8) & 0xFF;
  prdlen[1] = (rdlen     ) & 0xFF;
  
  return RCODE_OKAY;
}

/***********************************************************************/

static inline dns_rcode_t encode_rr_naptr(
	block_t           *const restrict data,
	const dns_naptr_t *const restrict naptr
)
{
  dns_rcode_t  rc;
  uint8_t     *prdlen;
  uint8_t     *pdata;
  
  assert(pblock_okay(data));
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
  
  rc = dns_encode_domain(data,naptr->name,strlen(naptr->name));
  if (rc != RCODE_OKAY) return rc;
  
  if (data->size < 14)	/* type, class, ttl */
    return RCODE_NO_MEMORY;
  
  write_uint16(data,naptr->type);
  write_uint16(data,naptr->class);
  write_uint32(data,naptr->ttl);
  
  /*-------------------------------------------------------------------------
  ; we need to come back to the rdlen after we've written the data.  We save
  ; a pointer to this point in the output block, allocate enough space for
  ; it, then save the start of the space we're about to write to, so later
  ; we can come back and write the length.
  ;-------------------------------------------------------------------------*/
  
  prdlen      = data->ptr;
  data->ptr  += sizeof(uint16_t);
  data->size -= sizeof(uint16_t);
  pdata       = data->ptr;

  write_uint16(data,naptr->order);
  write_uint16(data,naptr->preference);
  
  if ((rc = dns_encode_string(data,naptr->flags,   strlen(naptr->flags)))          != RCODE_OKAY) return rc;
  if ((rc = dns_encode_string(data,naptr->services,strlen(naptr->services)))       != RCODE_OKAY) return rc;
  if ((rc = dns_encode_string(data,naptr->regexp,  strlen(naptr->regexp)))         != RCODE_OKAY) return rc;
  if ((rc = dns_encode_domain(data,naptr->replacement,strlen(naptr->replacement))) != RCODE_OKAY) return rc;

  /*-----------------------------------------------------
  ; now write the length of the data we've just written
  ;-------------------------------------------------------*/
  
  write_uint16(&(block_t){ .ptr = prdlen , .size = 2 },data->ptr - pdata);
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

static bool align_memory(block_t *const pool)
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

static void *alloc_struct(block_t *const pool,const size_t size)
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

static inline void write_uint16(block_t *const parse,uint16_t value)
{
  assert(pblock_okay(parse));
  assert(parse->size >= 2);
  
  parse->ptr[0] = (value >> 8) & 0xFF;
  parse->ptr[1] = (value     ) & 0xFF;
  parse->ptr  += 2;
  parse->size -= 2;
}

/***********************************************************************/

static inline void write_uint32(block_t *const parse,uint32_t value)
{
  assert(pblock_okay(parse));
  assert(parse->size >= 4);
  
  parse->ptr[0] = (value >> 24) & 0xFF;
  parse->ptr[1] = (value >> 16) & 0xFF;
  parse->ptr[2] = (value >>  8) & 0xFF;
  parse->ptr[3] = (value      ) & 0xFF;
  parse->ptr  += 4;
  parse->size -= 4;
}

/***********************************************************************/

static inline uint16_t read_uint16(block_t *const parse)
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

static inline uint32_t read_uint32(block_t *const parse)
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
	idns_context  *const restrict data,
	uint8_t      **restrict       result,
	const size_t                  len
)
{
  assert(context_okay(data));
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
	idns_context  *const restrict data,
	const char   **restrict       result
)
{
  size_t len;
  
  assert(context_okay(data));
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
	idns_context  *const restrict data,
	const char   **restrict       result
)
{
  block_t *parse = &data->parse;
  block_t  tmp;
  size_t   len;
  int      loop;	/* loop detection */
  
  assert(context_okay(data));
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

      if (data->dest.size < len)
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
	idns_context *const restrict data,
	edns0_opt_t  *const restrict opt
)
{
  static const char hexdigits[] = "0123456789ABCDEF";
  
  if (opt->len % 2 == 1)
    return RCODE_FORMAT_ERROR;
    
  if (data->dest.size < opt->len / 2)
    return RCODE_NO_MEMORY;
  
  for (size_t i = 0 ; i < opt->len ; i += 2)
  {
    const char *phexh;
    const char *phexl;
    
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
	idns_context *const restrict data,
	edns0_opt_t  *const restrict opt
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
	idns_context   *const restrict data,
	dns_question_t *const restrict pquest
)
{
  dns_rcode_t rc;
  
  assert(context_okay(data));
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
	idns_context *const restrict data,
	dns_soa_t    *const restrict psoa,
	const size_t                 len
)
{
  dns_rcode_t rc;
  
  assert(context_okay(data));
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
	idns_context *const restrict data,
	dns_a_t      *const restrict pa,
	const size_t                 len
)
{
  assert(context_okay(data));
  assert(pa != NULL);

  if (len != 4) return RCODE_FORMAT_ERROR;
  memcpy(&pa->address,data->parse.ptr,4);
  data->parse.ptr  += 4;
  data->parse.size -= 4;
  return RCODE_OKAY;
}

/***********************************************************************/

static inline dns_rcode_t decode_rr_aaaa(
	idns_context *const restrict data,
	dns_aaaa_t   *const restrict pa,
	const size_t                 len
)
{
  assert(context_okay(data));
  assert(pa != NULL);
  
  if (len != 16) return RCODE_FORMAT_ERROR;
  memcpy(pa->address.s6_addr,data->parse.ptr,16);
  data->parse.ptr  += 16;
  data->parse.size -= 16;
  return RCODE_OKAY;
}

/**********************************************************************/

static inline dns_rcode_t decode_rr_wks(
	idns_context *const restrict data,
	dns_wks_t    *const restrict pwks,
	const size_t                 len
)
{
  assert(context_okay(data));
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
	idns_context *const restrict data,
	dns_mx_t     *const restrict pmx,
	const size_t                 len
)
{
  assert(context_okay(data));
  assert(pmx != NULL);

  if (len < 4) return RCODE_FORMAT_ERROR;
  
  pmx->preference = read_uint16(&data->parse);
  return read_domain(data,&pmx->exchange);
}

/**********************************************************************/

static inline dns_rcode_t decode_rr_txt(
	idns_context *const restrict data,
	dns_txt_t    *const restrict ptxt,
	const size_t                 len
)
{
  block_t tmp;
  size_t  worklen;
  size_t  items;
  size_t  slen;
  
  assert(context_okay(data));
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
  
  ptxt->text = (const char *)data->dest.ptr;

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
	idns_context *const restrict data,
	dns_hinfo_t  *const restrict phinfo
)
{
  dns_rcode_t rc;
  
  assert(context_okay(data));
  assert(phinfo != NULL);
  
  rc = read_string(data,&phinfo->cpu);
  if (rc != RCODE_OKAY) return rc;
  rc = read_string(data,&phinfo->os);
  return rc;
}

/**********************************************************************/

static inline dns_rcode_t decode_rr_srv(
	idns_context *const restrict data,
	dns_srv_t    *const restrict psrv,
	const size_t                 len
)
{
  assert(context_okay(data));
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
	idns_context *const restrict data,
	dns_naptr_t  *const restrict pnaptr,
	const size_t                 len
)
{
  dns_rcode_t rc;
  
  assert(context_okay(data));
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
	idns_context *const restrict data,
	dns_sig_t    *const restrict psig,
	const size_t                 len
)
{
  uint8_t     *start;
  size_t       sofar;
  dns_rcode_t  rc;
  
  assert(context_okay(data));
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
		idns_context *const restrict data,
		dns_minfo_t  *const restrict pminfo
)
{
  dns_rcode_t rc;
  
  assert(context_okay(data));
  assert(pminfo != NULL);
  
  rc = read_domain(data,&pminfo->rmailbx);
  if (rc != RCODE_OKAY) return rc;
  return read_domain(data,&pminfo->emailbx);
}

/*****************************************************************/

static dns_rcode_t dloc_double(idns_context *const restrict,double *const restrict) __attribute__ ((nonnull));

static dns_rcode_t dloc_double(
		idns_context *const restrict data,
		double       *const restrict pvalue
)
{
  size_t len;
 
  assert(context_okay(data));
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

static void dgpos_angle(dnsgpos_angle *const restrict,double) __attribute__ ((nonnull(1)));

static void dgpos_angle(
	dnsgpos_angle *const restrict pa,
	double                        v
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
		idns_context *const restrict data,
		dns_gpos_t   *const restrict pgpos
)
{
  dns_rcode_t rc;
  double      lat;
  double      lng;

  assert(context_okay(data));
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

#define LOC_BIAS	(((unsigned long)INT32_MAX) + 1uL)
#define LOC_LAT_MAX	((unsigned long)( 90uL * 3600000uL))
#define LOC_LNG_MAX	((unsigned long)(180uL * 3600000uL))
#define LOC_ALT_BIAS	(10000000L)

static int dloc_scale(unsigned long *const restrict,const int) __attribute__ ((nonnull(1)));

static int dloc_scale(
	unsigned long *const restrict presult,
	const int                     scale
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

static void dloc_angle(dnsgpos_angle *const restrict,const long) __attribute__ ((nonnull(1)));

static void dloc_angle(
	dnsgpos_angle *const restrict pa,
	const long                    v
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
		idns_context *const restrict data,
		dns_loc_t    *const restrict ploc,
		const size_t                 len
)
{
  dns_rcode_t    rc;
  unsigned long  lat;
  unsigned long  lng;
  
  assert(context_okay(data));
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
  
  if (lat >= LOC_BIAS)	/* north */
  {
    ploc->latitude.nw = true;
    lat -= LOC_BIAS;
  }
  else
    lat = LOC_BIAS - lat;
  
  if (lng >= LOC_BIAS)	/* east */
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
                idns_context   *const restrict data,
                dns_edns0opt_t *const restrict opt,
                const size_t                   len
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
    
    assert(context_okay(data));
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
		idns_context *const restrict data,
		dns_answer_t *const restrict pans
)
{
  size_t      len;
  size_t      rest;
  dns_rcode_t rc;
  
  assert(context_okay(data));
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

    if (data->parse.ptr[1] != 0)	/* version */
      return RCODE_FORMAT_ERROR;
    
    /*--------------------------------------------------------------------
    ; RFC-3225 states that of octets 2 and 3, only the left-most bit
    ; of byte 2 is defined (the DO bit)---the rest are supposed to be
    ; 0.  But of *course* Google is using these bits for their own
    ; "don't be evil" purposes, whatever that might be.
    ;
    ; Thaanks Google.  Thanks for being like Microsoft---embrace, extend and
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

dns_rcode_t dns_decode(
	      dns_decoded_t *const restrict presponse,
	      size_t        *const restrict prsize,
	const dns_packet_t  *const restrict buffer,
	const size_t                        len
)
{
  const struct idns_header *header;
  dns_query_t              *response;
  idns_context              context;
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
  
  if ((header->rcode & 0x40) != 0x00)	/* Z bit must be zero */
    return RCODE_FORMAT_ERROR;
  
  response->id      = ntohs(header->id);
  response->opcode  = (header->opcode >> 3) & 0x0F;
  response->query   = (header->opcode & 0x80) != 0x80;
  response->aa      = (header->opcode & 0x04) == 0x04;
  response->tc      = (header->opcode & 0x02) == 0x02;
  response->rd      = (header->opcode & 0x01) == 0x01;
  response->ra      = (header->rcode  & 0x80) == 0x80;
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
  
  /*-------------------------------------------------------------
  ; RR OPT can only appear once, and only in the additional info
  ; section.  Check that we haven't seen one before.
  ;-------------------------------------------------------------*/
  
  if (context.edns) return RCODE_FORMAT_ERROR;
  
  for (size_t i = 0 ; i < response->nscount ; i++)
  {
    rc = decode_answer(&context,&response->nameservers[i]);
    if (rc != RCODE_OKAY)
      return rc;
  }
  
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
