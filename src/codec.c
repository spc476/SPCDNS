
#include <limits.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>

#include <arpa/inet.h>

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

static block_t dns_encode_domain(block_t data,const dns_question_t *const restrict);

/***********************************************************************/

const char *const c_dns_rec_names[] =
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
    assert(query->qdcount >= 0);
    assert(query->qdcount <= SHRT_MAX);
    assert(query->ancount >= 0);
    assert(query->ancount <= SHRT_MAX);
    assert(query->nscount >= 0);
    assert(query->nscount <= SHRT_MAX);
    assert(query->arcount >= 0);
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
#endif

/*********************************************************************/

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
  
  for (int i = 0 ; i < query->qdcount ; i++)
  {
    data = dns_encode_domain(data,&query->questions[i]);
    if (data.err) return data.err;
  }
  
  /*----------------------------
  ; XXX - save answers for later
  ;-----------------------------*/
  
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

int dns_decode(
	dns_query_t   *restrict       response,
	const uint8_t *const restrict buffer,
	const size_t                  len
)
{
  const struct dns_header *header;
  
  header = (struct dns_header *)buffer;
  
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
  
  return 1;
}

/************************************************************************/

