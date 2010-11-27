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

#define _GNU_SOURCE

#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <math.h>
#include <assert.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include "dns.h"

/*----------------------------------------------------------------------------
; the folowing are used for memory allocation.  uintptr_t is picked as the
; alignment size, as it's good enough for alignment.  If some odd-ball
; system comes up that requires more strict alignment, then I'll change this
; to something like a long double or something silly like that.
;
; see the comment align_memory() for more details
;-----------------------------------------------------------------------------*/

#define MEM_ALIGN	sizeof(uintptr_t)
#define MEM_MASK	~(sizeof(uintptr_t) - 1uL)

/************************************************************************/

typedef struct block
{
  size_t          size;
  uint8_t        *ptr;
  enum dns_rcode  err;
} block_t;

struct idns_header
{
  uint16_t id 		__attribute__ ((packed));
  uint8_t  opcode	__attribute__ ((packed));
  uint8_t  rcode	__attribute__ ((packed));
  uint16_t qdcount	__attribute__ ((packed));
  uint16_t ancount	__attribute__ ((packed));
  uint16_t nscount	__attribute__ ((packed));
  uint16_t arcount	__attribute__ ((packed));
};

typedef struct idns_context
{
  block_t      packet;
  block_t      parse;
  block_t      dest;	/* see comments in align_memory() */
  dns_query_t *response;
} idns_context;

/***********************************************************************/

static        block_t	 dns_encode_domain(block_t,const dns_question_t *const restrict) __attribute__ ((nothrow,nonnull(2)));

static        bool	 align_memory	(block_t *const)		__attribute__ ((nothrow,nonnull,   warn_unused_result));
static        void      *alloc_struct	(block_t *const,const size_t)	__attribute__ ((nothrow,nonnull(1),warn_unused_result,malloc));
static inline uint16_t	 read_uint16	(block_t *const)		__attribute__ ((nothrow,nonnull));
static inline uint32_t	 read_uint32	(block_t *const)		__attribute__ ((nothrow,nonnull));

static        int        read_raw       (idns_context *const restrict,uint8_t    **restrict,const size_t) __attribute__ ((nothrow,nonnull(1,2)));
static        int        read_string    (idns_context *const restrict,const char **restrict)              __attribute__ ((nothrow,nonnull(1,2)));
static        int        read_domain    (idns_context *const restrict,const char **restrict)	          __attribute__ ((nothrow,nonnull));

static        int	 decode_question(idns_context *const restrict,dns_question_t *const restrict)		   __attribute__ ((nothrow,nonnull));
static inline int	 decode_rr_soa	(idns_context *const restrict,dns_soa_t      *const restrict,const size_t) __attribute__ ((nothrow,nonnull(1,2)));
static inline int	 decode_rr_a	(idns_context *const restrict,dns_a_t        *const restrict,const size_t) __attribute__ ((nothrow,nonnull(1,2)));
static inline int        decode_rr_wks  (idns_context *const restrict,dns_wks_t      *const restrict,const size_t) __attribute__ ((nothrow,nonnull(1,2)));
static inline int	 decode_rr_mx	(idns_context *const restrict,dns_mx_t       *const restrict,const size_t) __attribute__ ((nothrow,nonnull(1,2)));
static inline int	 decode_rr_txt	(idns_context *const restrict,dns_txt_t      *const restrict,const size_t) __attribute__ ((nothrow,nonnull(1,2)));
static inline int	 decode_rr_hinfo(idns_context *const restrict,dns_hinfo_t    *const restrict)              __attribute__ ((nothrow,nonnull(1,2)));
static inline int	 decode_rr_naptr(idns_context *const restrict,dns_naptr_t    *const restrict,const size_t) __attribute__ ((nothrow,nonnull(1,2)));
static inline int	 decode_rr_aaaa	(idns_context *const restrict,dns_aaaa_t     *const restrict,const size_t) __attribute__ ((nothrow,nonnull(1,2)));
static inline int	 decode_rr_srv	(idns_context *const restrict,dns_srv_t      *const restrict,const size_t) __attribute__ ((nothrow,nonnull(1,2)));
static inline int        decode_rr_sig  (idns_context *const restrict,dns_sig_t      *const restrict,const size_t) __attribute__ ((nothrow,nonnull(1,2)));
static inline int        decode_rr_rp   (idns_context *const restrict,dns_rp_t       *const restrict)              __attribute__ ((nothrow,nonnull(1,2)));
static inline int        decode_rr_gpos (idns_context *const restrict,dns_gpos_t     *const restrict)              __attribute__ ((nothrow,nonnull(1,2)));
static inline int        decode_rr_loc  (idns_context *const restrict,dns_loc_t      *const restrict,const size_t) __attribute__ ((nothrow,nonnull(1,2)));
static        int	 decode_answer	(idns_context *const restrict,dns_answer_t   *const restirct)              __attribute__ ((nothrow,nonnull(1,2)));

/***********************************************************************/

#ifndef NDEBUG
# include <syslog.h>

  static int query_okay  (const dns_query_t *const)  __attribute__ ((unused));
  static int pblock_okay (const block_t *const)      __attribute__ ((unused));
  static int block_okay  (const block_t)             __attribute__ ((unused));
  static int context_okay(const idns_context *const) __attribute__ ((unused));
  
  static int query_okay(const dns_query_t *const query)
  {
    assert(query          != NULL);
    assert(query->id      >= 0);
    assert(query->opcode  <= 2);
    assert(query->rcode   <= 5);
    assert(query->qdcount <= SHRT_MAX);
    assert(query->ancount <= SHRT_MAX);
    assert(query->nscount <= SHRT_MAX);
    assert(query->arcount <= SHRT_MAX);

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

#ifndef NDEBUG
# include <stdio.h>
# include <cgilib6/util.h>

  /*-------------------------------------------------------------------------
  ; this routine is only used for development and is *not* needed for normal
  ; operations.  You probably don't have the dump_memory() function defined
  ; (it's in a separate library on my (sean@conman.org) development system)
  ; so if you need to nuke this, go ahead.
  ;------------------------------------------------------------------------*/
  
  static void quick_dump(const char *,void *,size_t) __attribute__ ((unused));
  
  static void quick_dump(const char *tag,void *data,size_t len)
  {
    assert(tag != NULL);
    assert(data != NULL);
    assert(len  >  0);
    
    printf("\n%s\n",tag);
    dump_memory(stdout,data,len,0);
  }
#else
#  define quick_dump(t,d,l,o)
#endif

/*****************************************************************************/

int dns_encode(
	uint8_t           *const restrict buffer,
	size_t            *restrict       plen,
	const dns_query_t *const restrict query
)
{
  struct idns_header *header;
  block_t             data;
  
  assert(buffer != NULL);
  assert(plen   != NULL);
  assert(*plen  >= 12);
  assert(query  != NULL);
  
  memset(buffer,0,*plen);
  
  header = (struct idns_header *)buffer;
  
  header->id      = htons(query->id);
  header->opcode  = query->opcode << 3;
  header->rcode   = query->rcode;
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
  data.err  = RCODE_OKAY;
  
  for (size_t i = 0 ; i < query->qdcount ; i++)
  {
    data = dns_encode_domain(data,&query->questions[i]);
    if (data.err) return data.err;
  }
  
  /*------------------------------------------------------------
  ; at some point we may want to encode answers, nameservers,
  ; and additional records, but for now, we skip 'em
  ;-----------------------------------------------------------*/
  
  *plen = (size_t)(data.ptr - buffer);
  return RCODE_OKAY;
}

/*********************************************************************/

static block_t dns_encode_domain(
	block_t                              data,
	const dns_question_t *const restrict pquestion
)
{
  size_t   len;
  size_t   delta;
  uint8_t *start;
  uint8_t *end;
  uint8_t *back_ptr;
  
  assert(block_okay(data));
  assert(data.err         == RCODE_OKAY);
  assert(pquestion        != NULL);
  assert(pquestion->name  != NULL);
  assert(pquestion->class >= 1);
  assert(pquestion->class <= 4);
  
  len = strlen(pquestion->name);
  
  if (pquestion->name[len - 1] != '.')	/* name must be fully qualified */
  {
    data.err = RCODE_NAME_ERROR;
    return data;
  }
  
  if (data.size < len + 5)	/* not enough space */
  {
    data.err = RCODE_NAME_ERROR;
    return data;
  }
  
  memcpy(&data.ptr[1],pquestion->name,len);
  data.size -= (len + 5);
  
  back_ptr = data.ptr;
  start    = &data.ptr[1];
  end      = &data.ptr[1];
  
  while(len)
  {
    end   = memchr(start,'.',len);
    assert(end != NULL);	/* must be true---checked above */
  
    delta = (size_t)(end - start);
    assert(delta <= len);
    
    if (delta > 63)
    {
      data.err = RCODE_NAME_ERROR;
      return data;
    }
  
    *back_ptr  = (uint8_t)delta;
    back_ptr   = end;
    start      = end + 1;
    len       -= (delta + 1);
  }
  
  *back_ptr = 0;
  data.ptr  = end + 1;
  
  data.ptr[0] = (pquestion->type >> 8);
  data.ptr[1] = (pquestion->type & 0xFF);
  data.ptr[2] = (pquestion->class >> 8);
  data.ptr[3] = (pquestion->class & 0xFF);
  data.ptr += 4;
  
  return data;
}

/******************************************************************************
*
* Memory allocations are done quickly.  The dns_decode() routine is given a
* block of memory to carve allocations out of (8k is more than enough for
* UDP packets) and there's no real intelligence here---just a quick scheme. 
* String information is just allocated starting at the next available
* location (referenced in context->dest) whereas the few structures that do
* need allocating require the free pointer to be adjusted to a proper memory
* alignment.  If you need alignments, call alloc_struct(), otherwise for
* strings, use context->dest directly.  You *can* use align_memory()
* directly, just be sure you know what you are doing.
*
* If you are grabbing strings, just use context->dest directoy; othersise,
* call alloc_struct(), and don't forget to check for NULL.
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

static int read_raw(
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

    /*-----------------------------------------------------------------------
    ; read a raw block of data; the copy is structured aligned; this is really
    ; used when we don't know the structure of the data we're reading, so why
    ; not align it?
    ;-----------------------------------------------------------------------*/
    
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

static int read_string(
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

static int read_domain(
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
    
    /*-------------------------------------------
    ; EDNS0 OPT RR, not handled at this time
    ;-------------------------------------------*/
    
    else if ((*parse->ptr >= 64) && (*parse->ptr <= 127))
    {
      /* XXX - see RFC2671 for details */
      return RCODE_NOT_IMPLEMENTED;
    }
    
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

static int decode_question(
	idns_context   *const restrict data,
	dns_question_t *const restrict pquest
)
{
  int rc;
  
  assert(context_okay(data));
  assert(pquest != NULL);
  
  rc = read_domain(data,&pquest->name);
  if (rc != RCODE_OKAY)
    return rc;
  
  if (data->parse.size < 4)
    return RCODE_FORMAT_ERROR;
    
  pquest->type  = (enum dns_type) read_uint16(&data->parse);
  pquest->class = (enum dns_class)read_uint16(&data->parse);
  
  return RCODE_OKAY;
}

/************************************************************************/

static inline int decode_rr_soa(
	idns_context *const restrict data,
	dns_soa_t    *const restrict psoa,
	const size_t                 len
)
{
  enum dns_rcode rc;
  
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

static inline int decode_rr_a(
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

static inline int decode_rr_aaaa(
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

static inline int decode_rr_wks(
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

static inline int decode_rr_mx(
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

static inline int decode_rr_txt(
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
  }
  
  if (data->dest.size == 0)
    return RCODE_NO_MEMORY;
  
  *data->dest.ptr++ = '\0';
  data->dest.size--;
  
  return RCODE_OKAY;
}

/**********************************************************************/

static inline int decode_rr_hinfo(
	idns_context *const restrict data,
	dns_hinfo_t  *const restrict phinfo
)
{
  enum dns_rcode rc;
  
  assert(context_okay(data));
  assert(phinfo != NULL);
  
  rc = read_string(data,&phinfo->cpu);
  if (rc != RCODE_OKAY) return rc;
  rc = read_string(data,&phinfo->os);
  return rc;
}

/**********************************************************************/

static inline int decode_rr_srv(
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

static inline int decode_rr_naptr(
	idns_context *const restrict data,
	dns_naptr_t  *const restrict pnaptr,
	const size_t                 len
)
{
  enum dns_rcode rc;
  
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

static inline int decode_rr_sig(
	idns_context *const restrict data,
	dns_sig_t    *const restrict psig,
	const size_t                 len
)
{
  uint8_t        *start;
  size_t          sofar;
  enum dns_rcode  rc;
  
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

static inline int decode_rr_rp(
		idns_context *const restrict data,
		dns_rp_t     *const restrict prp
)
{
  enum dns_rcode rc;
  
  assert(context_okay(data));
  assert(prp != NULL);
  
  rc = read_domain(data,&prp->mbox);
  if (rc != RCODE_OKAY) return rc;
  return read_domain(data,&prp->domain);
}

/*****************************************************************/

static enum dns_rcode dloc_double(idns_context *const restrict,double *const restrict) __attribute__ ((nonnull));

static enum dns_rcode dloc_double(
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

/*****************************************************************/

static inline int decode_rr_gpos(
		idns_context *const restrict data,
		dns_gpos_t   *const restrict pgpos
)
{
  enum dns_rcode rc;

  assert(context_okay(data));
  assert(pgpos != NULL);
  
  rc = dloc_double(data,&pgpos->longitude);
  if (rc != RCODE_OKAY) return rc;
  rc = dloc_double(data,&pgpos->latitude);
  if (rc != RCODE_OKAY) return rc;
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

static void dloc_angle(dnsloc_angle *const restrict,const long) __attribute__ ((nonnull(1)));

static void dloc_angle(
	dnsloc_angle *const restrict pa,
	const long                   v
)
{
  ldiv_t partial;
  
  partial  = ldiv(v,1000L);
  pa->frac = partial.rem;
  partial  = ldiv(partial.quot,60L);
  pa->sec  = partial.rem;
  partial  = ldiv(partial.quot,60L);
  pa->min  = partial.rem;
  pa->deg  = partial.quot;
}

/*************************************************************/

static inline int decode_rr_loc(
		idns_context *const restrict data,
		dns_loc_t    *const restrict ploc,
		const size_t                 len
)
{
  enum dns_rcode rc;
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
  
  if (lng >= LOC_BIAS)	/* west */
  {
    ploc->longitude.nw = true;
    lng -= LOC_BIAS;
  }
  else
    lng = LOC_BIAS - lng;

  if (lat > LOC_LAT_MAX)
    return RCODE_FORMAT_ERROR;
  
  if (lng > LOC_LNG_MAX)
    return RCODE_FORMAT_ERROR;
  
  dloc_angle(&ploc->latitude ,lat);
  dloc_angle(&ploc->longitude,lng);
  
  return RCODE_OKAY;
}

/***************************************************************/

static int decode_answer(
		idns_context *const restrict data,
		dns_answer_t *const restrict pans
)
{
  size_t         len;
  size_t         rest;
  enum dns_rcode rc;
  
  assert(context_okay(data));
  assert(pans != NULL);
  
  rc = read_domain(data,&pans->generic.name);
  if (rc != RCODE_OKAY)
    return rc;
  
  if (data->parse.size < 10)
    return RCODE_FORMAT_ERROR;
    
  pans->generic.type  = read_uint16(&data->parse);
  pans->generic.class = read_uint16(&data->parse);
  pans->generic.ttl   = read_uint32(&data->parse);
  
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
    
    /*----------------------------------------------------------------------	
    ; The following record types all share the same structure (although the
    ; last field name is different, depending upon the record), so they can
    ; share the same call site.  It's enough to shave some space in the
    ; executable while being a cheap and non-obscure size optimization, or
    ; a gross hack, depending upon your view.
    ;----------------------------------------------------------------------*/
    
    case RR_PX:
    case RR_RP: return decode_rr_rp(data,&pans->rp);
    
    case RR_AFSDB:
    case RR_RT:
    case RR_MX: return decode_rr_mx(data,&pans->mx,len);
    
    case RR_NSAP:
    case RR_ISDN:
    case RR_MINFO:
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
    case RR_EID:
    case RR_NIMLOC:
    case RR_ATM:
    case RR_KX:
    case RR_CERT:
    case RR_SINK:
    default: return read_raw(data,&pans->x.rawdata,len);
  }
  
  assert(0);
  return RCODE_OKAY;
}

/***********************************************************************/

int dns_decode(
	      void    *const restrict presponse,
	const size_t                  rsize,
	const uint8_t *const restrict buffer,
	const size_t                  len
)
{
  const struct idns_header *header;
  dns_query_t              *response;
  idns_context              context;
  int                       rc;

  assert(presponse != NULL);
  assert(rsize     >= 8192);
  assert(buffer    != NULL);
  assert(len       >= sizeof(struct idns_header));
  
  context.packet.ptr  = (uint8_t *)buffer;
  context.packet.size = len;
  context.parse.ptr   = (uint8_t *)&buffer[sizeof(struct idns_header)];
  context.parse.size  = len - sizeof(struct idns_header);
  context.dest.ptr    = presponse;
  context.dest.size   = rsize;
  
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
  
  for (size_t i = 0 ; i < response->nscount ; i++)
  {
    rc = decode_answer(&context,&response->nameservers[i]);
    if (rc != RCODE_OKAY)
      return rc;
  }
  
  for (size_t i = 0 ; i < response->arcount ; i++)
  {
    rc = decode_answer(&context,&response->additional[i]);
    if (rc != RCODE_OKAY)
      return rc;
  }

#ifndef NDEBUG  
  syslog(
  	LOG_DEBUG,
  	"used %lu bytes",
  	(unsigned long)(context.dest.ptr - (uint8_t *)response)
  );
#endif

  return RCODE_OKAY;
}

/************************************************************************/
