
#ifndef DNS_H
#define DNS_H

#define MAX_DNS_QUERY_SIZE	512
#define MAX_DOMAIN_SEGMENT	 64
#define MAX_STRING_LEN		256

enum dns_type
{
  RR_min   =  1,

  RR_A     =  1,	/* IPv4 Address 		*/ /* RFC-1035 */
  RR_NS    =  2,	/* Name server			*/
  RR_MD    =  3,	/* Mail Destination (obsolete)	*/
  RR_MF    =  4,	/* Mail Forwarder (obsolete)	*/
  RR_CNAME =  5,	/* Canonical name		*/
  RR_SOA   =  6,	/* Start of Authority		*/
  RR_MB    =  7,	/* Mailbox (experimental)	*/
  RR_MG    =  8,	/* Mailgroup (experimental)	*/
  RR_MR    =  9,	/* Mailrename (experimental)	*/
  RR_NULL  = 10,	/* NULL resource (experimental)	*/
  RR_WKS   = 11,	/* Well Known Service		*/
  RR_PTR   = 12,	/* Pointer			*/
  RR_HINFO = 13,	/* Host Info			*/
  RR_MINFO = 14,	/* Mailbox/mail list info	*/
  RR_MX    = 15,	/* Mail Exchange		*/
  RR_TXT   = 16,	/* Text				*/

  RR_NAPTR = 35,	/* Naming Authority Pointer	*/ /* RFC-2915 */
  
  RR_ANY   = 255,
  RR_max
};

enum dns_class
{
  CLASS_min = 1,
  CLASS_IN  = 1,	/* Internet			*/
  CLASS_CS,		/* CSNET - obsolete		*/
  CLASS_CH,		/* CHAOS			*/
  CLASS_HS,		/* Hesiod			*/
  CLASS_max
};

enum dns_op
{
  OP_min    = 0,
  OP_QUERY  = 0,
  OP_IQUERY,
  OP_STATUS,
  OP_max
};

enum dns_rcode
{
  RCODE_min  = 0,
  RCODE_OKAY = 0,
  RCODE_FORMAT_ERROR,
  RCODE_SERVER_FAILURE,
  RCODE_NAME_ERROR,
  RCODE_NOT_IMPLEMENTED,
  RCODE_REFUSED,

  RCODE_DOMAIN_ERROR = 200,
  RCODE_DOMAIN_LOOP,
  RCODE_QUESTION_BAD,
  RCODE_MX_BAD_RECORD,
  RCODE_ANSWER_BAD,
  RCODE_BAD_LENGTH,
  RCODE_A_BAD_ADDR,
  RCODE_SOA_BAD_LEN,
  RCODE_UNKNOWN_OPTIONS,
  RCODE_NO_MEMORY,
  
  RCODE_max
};  

typedef uint32_t TTL;

typedef struct dns_question_t
{
  const char     *name;
  enum dns_type   type;
  enum dns_class  class;
} dns_question_t;

typedef struct dns_generic_t
{
  const char     *name;
  enum dns_type   type;
  enum dns_class  class;
  TTL             ttl;
} dns_generic_t;

typedef struct dns_x_t
{
  const char     *name;
  enum dns_type   type;
  enum dns_class  class;
  TTL             ttl;
  size_t          size;
  uint8_t        *rawdata;
} dns_x_t;

typedef struct dns_soa_t
{
  const char     *name;
  enum dns_type   type;
  enum dns_class  class;
  TTL             ttl;
  const char     *mname;
  const char     *rname;
  uint32_t        serial;
  uint32_t        refresh;
  uint32_t        retry;
  uint32_t        expire;
  uint32_t        minimum;
} dns_soa_t;

typedef struct dns_a_t
{
  const char     *name;
  enum dns_type   type;
  enum dns_class  class;
  TTL             ttl;
  in_addr_t       address;
} dns_a_t;

typedef struct dns_cname_t
{
  const char     *name;
  enum dns_type   type;
  enum dns_class  class;
  TTL             ttl;
  const char     *cname;
} dns_cname_t;

typedef struct dns_ns_t
{
  const char     *name;
  enum dns_type   type;
  enum dns_class  class;
  TTL             ttl;
  const char     *nsdname;
} dns_ns_t;

typedef struct dns_mb_t
{
  const char     *name;
  enum dns_type   type;
  enum dns_class  class;
  TTL             ttl;
  const char     *madname;
} dns_mb_t;

typedef struct dns_md_t
{
  const char     *name;
  enum dns_type   type;
  enum dns_class  class;
  TTL             ttl;
  const char     *madname;
} dns_md_t;

typedef struct dns_mf_t
{
  const char     *name;
  enum dns_type   type;
  enum dns_class  class;
  TTL             ttl;
  const char     *madname;
} dns_mf_t;

typedef struct dns_mg_t
{
  const char     *name;
  enum dns_type   type;
  enum dns_class  class;
  TTL             ttl;
  const char     *mgmname;
} dns_mg_t;

typedef struct dns_mr_t
{
  const char     *name;
  enum dns_type   type;
  enum dns_class  class;
  TTL             ttl;
  const char     *newname;
} dns_mr_t;

typedef struct dns_ptr_t
{
  const char     *name;
  enum dns_type   type;
  enum dns_class  class;
  TTL             ttl;
  const char     *ptr;
} dns_ptr_t;

typedef struct dns_txt_t
{
  const char     *name;
  enum dns_type   type;
  enum dns_class  class;
  TTL             ttl;
  const char     *txt;
} dns_txt_t;

typedef struct dns_mx_t
{
  const char     *name;
  enum dns_type   type;
  enum dns_class  class;
  TTL             ttl;
  int             preference;
  const char     *exchange;
} dns_mx_t;

typedef struct dns_hinfo_t
{
  const char     *name;
  enum dns_type   type;
  enum dns_class  class;
  TTL             ttl;
  const char     *cpu;
  const char     *os;
} dns_hinfo_t;

typedef struct dns_minfo_t
{
  const char     *name;
  enum dns_type   type;
  enum dns_class  class;
  TTL             ttl;
  const char     *rmailbx;
  const char     *emailbx;
} dns_minfo_t;

typedef struct dns_naptr_t	/* RFC-2915 */
{
  const char     *name;
  enum dns_type   type;
  enum dns_class  class;
  TTL             ttl;
  int             order;
  int             preference;
  const char     *flags;
  const char     *services;
  const char     *regexp;
  const char     *replacement;
} dns_naptr_t;

typedef union dns_answer_t
{
  dns_generic_t generic;
  dns_soa_t     soa;
  dns_mx_t      mx;
  dns_a_t       a;
  dns_cname_t   cname;
  dns_ns_t      ns;
  dns_txt_t     txt;
  dns_mb_t      mb;
  dns_md_t      md;
  dns_mf_t      mf;
  dns_mg_t      mg;
  dns_mr_t      mr;
  dns_hinfo_t   hinfo;
  dns_minfo_t   minfo;
  dns_ptr_t     ptr;
  dns_naptr_t   naptr;
  dns_x_t       x;
} dns_answer_t;

typedef struct dns_query_t
{
  int             id;
  bool            query;
  enum dns_op     opcode;
  bool            aa;
  bool            tc;
  bool            rd;
  bool            ra;
  enum dns_rcode  rcode;
  size_t          qdcount;
  size_t          ancount;
  size_t          nscount;
  size_t          arcount;
  dns_question_t *questions;
  dns_answer_t   *answers;
  dns_answer_t   *nameservers;
  dns_answer_t   *additional;
} dns_query_t;

/**********************************************************************/

int	dns_encode	(
			  uint8_t           *restrict,
			  size_t            *restrict,
			  const dns_query_t *const restrict
			) __attribute__ ((nonnull));

int	dns_decode	(
                          void *const restrict,
                          const size_t,
			  const uint8_t *const restrict,
			  const size_t
			) __attribute__ ((nonnull(1,3)));

#endif
