
#define _GNU_SOURCE

#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include "dns.h"

#define MAX_UDP		(  8uL * 1024uL)
#define MAX_TCP 	(128uL * 1024uL)
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
  block_t      dest;
  dns_query_t *response;
} idns_context;

/***********************************************************************/

static        bool	 align_memory	(block_t *const)				__attribute__ ((nonnull));
static        void      *alloc_struct	(block_t *const,const size_t)			__attribute__ ((nonnull(1)));
static inline uint16_t	 read_uint16	(block_t *const)				__attribute__ ((nonnull));
static inline uint32_t	 read_uint32	(block_t *const)				__attribute__ ((nonnull));
static        int        read_raw       (idns_context *const restrict,uint8_t    **restrict,const size_t) __attribute__ ((nonnull(1,2)));
static        int        read_domain    (idns_context *const restrict,const char **restrict)	__attribute__ ((nonnull));

static        block_t  dns_encode_domain(block_t,const dns_question_t *const restrict)	__attribute__ ((nonnull(2)));

static        int      decode_question	(idns_context *const restrict,dns_question_t *const restrict)		   __attribute__ ((nonnull));
static inline int      decode_rr_soa    (idns_context *const restrict,dns_soa_t      *const restrict,const size_t) __attribute__ ((nonnull(1,2)));
static inline int      decode_rr_a	(idns_context *const restrict,dns_a_t        *const restrict,const size_t) __attribute__ ((nonnull(1,2)));
static inline int      decode_rr_mx     (idns_context *const restrict,dns_mx_t       *const restrict,const size_t) __attribute__ ((nonnull(1,2)));
static inline int      decode_rr_txt	(idns_context *const restrict,dns_txt_t      *const restrict,const size_t) __attribute__ ((nonnull(1,2)));
static inline int      decode_rr_hinfo	(idns_context *const restrict,dns_hinfo_t    *const restrict)              __attribute__ ((nonnull(1,2)));
static inline int      decode_rr_minfo	(idns_context *const restrict,dns_minfo_t    *const restrict)              __attribute__ ((nonnull(1,2)));
static        int      decode_answer    (idns_context *const restrict,dns_answer_t   *const restirct)              __attribute__ ((nonnull(1,2)));

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

/******************************************************************/

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
    
    *result = data->dest.ptr;
    memcpy(data->dest.ptr,data->parse.ptr,len);
    data->parse.ptr  += len;
    data->parse.size -= len;
  }
  else
    *result = NULL;
    
  return RCODE_OKAY;
}

/********************************************************************/

static int read_domain(idns_context *const restrict data,const char **restrict result)
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
    if (*parse->ptr < 64)
    {
      len = *parse->ptr;
      
      if (parse->size < len + 1)
        return RCODE_DOMAIN_ERROR;

      memcpy(data->dest.ptr,&parse->ptr[1],len);
      parse->ptr         += (len + 1);
      parse->size        -= (len + 1);
      data->dest.size   -= (len + 1);
      data->dest.ptr    += len;
      *data->dest.ptr++  = '.';
    }
    else if (*parse->ptr >= 192)
    {
      if (++loop == 256)
        return RCODE_DOMAIN_LOOP;
      
      if (parse->size < 2)
        return RCODE_DOMAIN_ERROR;
      
      len = read_uint16(parse) & 0x3FFF;
      
      if (len >= data->packet.size)
        return RCODE_DOMAIN_ERROR;
      
      tmp.ptr = &data->packet.ptr[len];
      tmp.size = data->packet.size - (size_t)(tmp.ptr - data->packet.ptr);
      parse    = &tmp;
    }
    else
      return RCODE_DOMAIN_ERROR;

  } while (*parse->ptr);
  
  parse->ptr++;
  parse->size--;
  *data->dest.ptr++ = '\0';
  data->dest.size--;
  
  return RCODE_OKAY;
}

/********************************************************************/

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
  
  header = (struct idns_header *)buffer;
  
  header->id      = htons(query->id);
  header->opcode  = query->opcode << 3;
  header->rcode   = query->rcode;
  header->qdcount = htons(query->qdcount);
  header->ancount = htons(query->ancount);
  header->nscount = htons(query->nscount);
  header->arcount = htons(query->arcount);
  
  if (!query->query) header->opcode |= 0x80;
  if (query->aa)     header->opcode |= 0x04;
  if (query->tc)     header->opcode |= 0x02;
  if (query->rd)     header->opcode |= 0x01;
  if (query->ra)     header->rcode  |= 0x80;
  
  data.size = *plen - 12;
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
  
  assert(data.size        >  0);
  assert(data.ptr         != NULL);
  assert(data.err         == RCODE_OKAY);
  assert(pquestion        != NULL);
  assert(pquestion->name  != NULL);
  assert(pquestion->type  <= RR_max);
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

/***********************************************************************/

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
    return RCODE_QUESTION_BAD;
  
  if (data->parse.size < 4)
    return RCODE_QUESTION_BAD;
    
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
    return RCODE_SOA_BAD_LEN;
  
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
  assert(data != NULL);
  assert(pa   != NULL);

  if (len != 4) return RCODE_A_BAD_ADDR;
  memcpy(&pa->address,data->parse.ptr,4);
  data->parse.ptr  += 4;
  data->parse.size -= 4;
  return RCODE_OKAY;
}

/***********************************************************************/

static inline int decode_rr_mx(
	idns_context *const restrict data,
	dns_mx_t     *const restrict pmx,
	const size_t                 len
)
{
  assert(context_okay(data));
  assert(pmx != NULL);

  if (len < 4) return RCODE_MX_BAD_RECORD;
  
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
  assert(context_okay(data));
  assert(ptxt != NULL);

  data->parse.ptr  += len;
  data->parse.size -= len;
  return RCODE_OKAY;
}

/**********************************************************************/

static inline int decode_rr_hinfo(
	idns_context *const restrict data,
	dns_hinfo_t  *const restrict phinfo
)
{
  enum dns_rcode rc;
  
  rc = read_domain(data,&phinfo->cpu);
  if (rc != RCODE_OKAY) return rc;
  rc = read_domain(data,&phinfo->os);
  return rc;
}

/**********************************************************************/

static inline int decode_rr_minfo(
	idns_context *const restrict data,
	dns_minfo_t  *const restrict pminfo
)
{
  enum dns_rcode rc;
  
  rc = read_domain(data,&pminfo->rmailbx);
  if (rc != RCODE_OKAY) return rc;
  rc = read_domain(data,&pminfo->emailbx);
  return rc;
}

/*********************************************************************/

static int decode_answer(
		idns_context *const restrict data,
		dns_answer_t *const restrict pans
)
{
  size_t         len;
  size_t         rest;
  
  assert(context_okay(data));
  assert(pans != NULL);
  
  if (read_domain(data,&pans->generic.name) != RCODE_OKAY)
    return RCODE_DOMAIN_ERROR;
  
  if (data->parse.size < 10)
    return RCODE_ANSWER_BAD;
    
  pans->generic.type  = read_uint16(&data->parse);
  pans->generic.class = read_uint16(&data->parse);
  pans->generic.ttl   = read_uint32(&data->parse);
  
  len  = read_uint16(&data->parse);
  rest = data->packet.size - (data->parse.ptr - data->packet.ptr);
  if (len > rest) 
    return RCODE_BAD_LENGTH;

  switch(pans->generic.type)
  {
    case RR_A:     return decode_rr_a    (data,&pans->a,len);
    case RR_NS:    return read_domain    (data,&pans->ns.nsdname);
    case RR_MD:    return read_domain    (data,&pans->md.madname);
    case RR_MF:    return read_domain    (data,&pans->mf.madname);
    case RR_CNAME: return read_domain    (data,&pans->cname.cname);
    case RR_SOA:   return decode_rr_soa  (data,&pans->soa,len);
    case RR_MB:    return read_domain    (data,&pans->mb.madname);
    case RR_MG:    return read_domain    (data,&pans->mg.mgmname);
    case RR_MR:    return read_domain    (data,&pans->mr.newname);
    case RR_NULL:  return read_raw       (data,&pans->x.rawdata,len);
    case RR_WKS:   return read_raw       (data,&pans->x.rawdata,len);
    case RR_PTR:   return read_domain    (data,&pans->ptr.ptr);
    case RR_HINFO: return decode_rr_hinfo(data,&pans->hinfo);
    case RR_MINFO: return decode_rr_minfo(data,&pans->minfo);
    case RR_MX:    return decode_rr_mx   (data,&pans->mx ,len);
    case RR_TXT:   return decode_rr_txt  (data,&pans->txt,len);
    default:       return read_raw       (data,&pans->x.rawdata,len);
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
  
  response         = (dns_query_t *)context.dest.ptr;
  context.response = alloc_struct(&context.dest,sizeof(dns_query_t));
  
  assert(context.response != NULL);
  assert(context.response == response);
  
  memset(response,0,sizeof(dns_query_t));
  response->questions   = NULL;
  response->answers     = NULL;
  response->nameservers = NULL;
  response->additional  = NULL;
  
  header      = (struct idns_header *)buffer;
  
  if ((header->rcode & 0x70) != 0x00)
    return free(response) , RCODE_UNKNOWN_OPTIONS;
  
  response->id      = ntohs(header->id);
  response->opcode  = (header->opcode >> 3) & 0x0F;
  response->query   = (header->opcode & 0x80) != 0x80;
  response->aa      = (header->opcode & 0x04) == 0x04;
  response->tc      = (header->opcode & 0x02) == 0x02;
  response->rd      = (header->opcode & 0x01) == 0x01;
  response->ra      = (header->rcode  & 0x80) == 0x80;
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
