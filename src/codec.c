
#define _GNU_SOURCE

#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include "dns.h"

/************************************************************************/

typedef struct block
{
  size_t          size;
  uint8_t        *ptr;
  enum dns_rcode  err;
} block_t;

struct dns_header
{
  uint16_t id 		__attribute__ ((packed));
  uint8_t  opcode	__attribute__ ((packed));
  uint8_t  rcode	__attribute__ ((packed));
  uint16_t qdcount	__attribute__ ((packed));
  uint16_t ancount	__attribute__ ((packed));
  uint16_t nscount	__attribute__ ((packed));
  uint16_t arcount	__attribute__ ((packed));
};

/***********************************************************************/

static inline uint16_t read_uint16		(block_t *const)                                  					__attribute__ ((nonnull));
static inline uint32_t read_uint32              (block_t *const)									__attribute__ ((nonnull));
static        block_t  dns_encode_domain	(block_t,const dns_question_t *const restrict)    					__attribute__ ((nonnull(2)));
static        int      read_domain		(const block_t *const restrict,block_t *const restrict,block_t *const restrict)		__attribute__ ((nonnull));
static        int      decode_question		(dns_question_t *const restrict,const block_t *const restrict,block_t *const restrict)	__attribute__ ((nonnull));
static        int      decode_answer            (dns_answer_t   *const restrict,const block_t *const restrict,block_t *const restrict)	__attribute__ ((nonnull));

static block_t dns_encode_domain(block_t data,const dns_question_t *const restrict);

/***********************************************************************/

const char *const c_dns_type_names[] =
{
  "UNKN",
  "A",
  "NS",
  "MD",
  "MF",
  "CNAME",
  "SOA",
  "MB",
  "MG",
  "MR",
  "NULL",
  "WKS",
  "PTR",
  "HINFO",
  "MINFO",
  "MX",
  "TXT"
};

const char *const c_dns_class_names[] = 
{
  "??",
  "IN",
  "CS",
  "CH",
  "HS"
};

const char *const c_dns_op_names[] =
{
  "QUERY",
  "IQUERY",
  "STATUS"
};

const char *const c_dns_result_names[] =
{
  "Ok",
  "Format error",
  "Server failure",
  "Name error",
  "Not implemented",
  "Refused"
};

/***********************************************************************/

#ifndef NDEBUG
  int check_query(const dns_query_t *const query)
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
#else
#  define check_query(q)
#endif

/*********************************************************************/

#ifndef NDEBUG
# include <stdio.h>
# include <cgilib6/util.h>
  void quick_dump(const char *tag,void *data,size_t len)
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

static inline uint16_t read_uint16(block_t *const parse)
{
  uint16_t val;
  
  assert(parse       != NULL);
  assert(parse->ptr  != NULL);
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
  
  assert(parse       != NULL);
  assert(parse->ptr  != NULL);
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

int dns_encode(
	uint8_t           *const restrict buffer,
	size_t            *restrict       plen,
	const dns_query_t *const restrict query
)
{
  struct dns_header *header;
  block_t data;
  
  assert(buffer != NULL);
  assert(plen   != NULL);
  assert(*plen  >= 12);
  assert(check_query(query));
  
  header = (struct dns_header *)buffer;
  
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
  data.ptr  = &buffer[sizeof(struct dns_header)];
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
  assert(pquestion->type  <= 16);
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

static int read_domain(
	const block_t *const restrict packet,
	      block_t *const restrict pparse,
	      block_t *const restrict dest
)
{
  block_t *parse = pparse;
  block_t  tmp;
  size_t   len;
  
  assert(packet       != NULL);
  assert(packet->ptr  != NULL);
  assert(packet->size >  0);
  assert(pparse       != NULL);
  assert(pparse->ptr  != NULL);
  assert(pparse->size >  0);
  assert(dest         != NULL);
  assert(dest->ptr    != NULL);
  assert(dest->size   >  0);

  do
  {
    if (*parse->ptr < 64)
    {
      len = *parse->ptr;
      
      if (parse->size < len + 1)
        return RCODE_DOMAIN_ERROR;

      memcpy(dest->ptr,&parse->ptr[1],len);
      parse->ptr   += (len + 1);
      parse->size  -= (len + 1);
      dest->size   -= (len + 1);
      dest->ptr    += len;
      *dest->ptr++  = '.';
    }
    else if (*parse->ptr >= 192)
    {
      if (parse->size < 2)
        return RCODE_DOMAIN_ERROR;
      
      len = read_uint16(parse) & 0x3FFF;
      
      if (len >= packet->size)
        return RCODE_DOMAIN_ERROR;
      
      tmp.ptr = &packet->ptr[len];
      tmp.size = packet->size - (size_t)(tmp.ptr - packet->ptr);
      parse    = &tmp;
    }
    else
      return RCODE_DOMAIN_ERROR;

  } while (*parse->ptr);
  
  parse->ptr++;
  parse->size--;
  *dest->ptr++ = '\0';
  dest->size--;
  
  return RCODE_OKAY;
}

/************************************************************************/

static int decode_question(
	      dns_question_t *const restrict pquest,
	const block_t        *const restrict packet,
	      block_t        *const restrict parse
)
{
  uint8_t buffer[MAX_STRING_LEN];
  block_t dest;
  
  assert(pquest       != NULL);
  assert(packet       != NULL);
  assert(packet->ptr  != NULL);
  assert(packet->size >  0);
  assert(parse        != NULL);
  assert(parse->ptr   != NULL);
  assert(parse->size  >  0);
  
  dest.ptr  = buffer;
  dest.size = sizeof(buffer);
  
  read_domain(packet,parse,&dest);
  pquest->name  = strdup((char *)buffer);
  pquest->type  = (enum dns_type)read_uint16(parse);
  pquest->class = (enum dns_class)read_uint16(parse);
  
  if ((pquest->type < RR_min) || (pquest->type >= RR_max))
    return RCODE_TYPE_ERROR;
  
  if ((pquest->type < CLASS_min) || (pquest->class >= CLASS_max))
    return RCODE_TYPE_ERROR;
  
  return RCODE_OKAY;
}

/************************************************************************/

static int decode_answer(
	      dns_answer_t *const restrict pans,
	const block_t      *const restrict packet,
	      block_t      *const restrict parse
)
{
  uint8_t        buffer[MAX_STRING_LEN];
  block_t        dest;
  
  assert(pans         != NULL);
  assert(packet       != NULL);
  assert(packet->ptr  != NULL);
  assert(packet->size >  0);
  assert(parse        != NULL);
  assert(parse->ptr   != NULL);
  assert(parse->size  >  0);
  
  dest.ptr  = buffer;
  dest.size = sizeof(buffer);
  
  if (read_domain(packet,parse,&dest) != RCODE_OKAY)
    return RCODE_DOMAIN_ERROR;
  
  pans->generic.name  = strdup((char *)buffer);
  pans->generic.type  = (enum dns_type)read_uint16(parse);
  pans->generic.class = (enum dns_class)read_uint16(parse);
  pans->generic.ttl   = read_uint32(parse);
  
  if ((pans->generic.type < RR_min) || (pans->generic.type >= RR_max))
    return RCODE_TYPE_ERROR;
  
  if ((pans->generic.class < CLASS_min) || (pans->generic.class >= CLASS_max))
    return RCODE_CLASS_ERROR;

  /* FIXME - skip rest of packet for now */
  
  size_t len   = read_uint16(parse);
  parse->ptr  += len;
  parse->size -= len;
  return RCODE_OKAY;
}

/***********************************************************************/

int dns_decode(
	      dns_query_t *restrict       response,
	const uint8_t     *const restrict buffer,
	const size_t                      len
)
{
  const struct dns_header *header;
  block_t                  packet;
  block_t                  parse;
  int                      rc;
  
  assert(response != NULL);
  assert(buffer   != NULL);
  assert(len      >  0);
  
  memset(response,0,sizeof(dns_query_t));
  response->questions   = NULL;
  response->answers     = NULL;
  response->nameservers = NULL;
  response->additional  = NULL;
  
  packet.ptr  = (uint8_t *)buffer;
  packet.size = len;
  parse.ptr   = (uint8_t *)&buffer[sizeof(struct dns_header)];
  parse.size  = len - sizeof(struct dns_header);
  header      = (struct dns_header *)buffer;
  
  if ((header->rcode & 0x70) != 0x00)
    return response->rcode = RCODE_UNKNOWN_OPTIONS;
  
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

  response->questions   = malloc(response->qdcount * sizeof(dns_question_t));
  response->answers     = malloc(response->ancount * sizeof(dns_answer_t));
  response->nameservers = malloc(response->nscount * sizeof(dns_answer_t));
  response->additional  = malloc(response->arcount * sizeof(dns_answer_t));
  
  if (
          (response->qdcount && (response->questions   == NULL))
       || (response->ancount && (response->answers     == NULL))
       || (response->nscount && (response->nameservers == NULL))
       || (response->arcount && (response->additional  == NULL))
     )
  {
    response->rcode = RCODE_NO_MEMORY;
    return RCODE_NO_MEMORY;
  }
  
  for (size_t i = 0 ; i < response->qdcount ; i++)
  {
    rc = decode_question(&response->questions[i],&packet,&parse);
    if (rc != RCODE_OKAY)
    {
      response->rcode = rc;
      return rc;
    }
  }

  for (size_t i = 0 ; i < response->ancount ; i++)
  {
    rc = decode_answer(&response->answers[i],&packet,&parse);
    if (rc != RCODE_OKAY)
      return response->rcode = rc;
  }
  
  for (size_t i = 0 ; i < response->nscount ; i++)
  {
    rc = decode_answer(&response->nameservers[i],&packet,&parse);
    if (rc != RCODE_OKAY)
      return response->rcode = rc;
  }
  
  for (size_t i = 0 ; i < response->arcount ; i++)
  {
    rc = decode_answer(&response->additional[i],&packet,&parse);
    if (rc != RCODE_OKAY)
      return response->rcode = rc;
  }
  
  return RCODE_OKAY;
}

/************************************************************************/
