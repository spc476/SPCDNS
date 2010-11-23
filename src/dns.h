
#ifndef DNS_H
#define DNS_H

#define MAX_DNS_QUERY_SIZE	512
#define MAX_DOMAIN_SEGMENT	 64
#define MAX_STRING_LEN		256

enum dns_type
{
  RR_min   =  1,
  RR_A     =  1,	/* IPv4 Address 		*/
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
  RR_max
};

enum dns_class
{
  CLASS_min = 1,
  CLASS_IN  = 1,	/* Internet			*/
  CLASS_CS  = 2,	/* CSNET - obsolete		*/
  CLASS_CH  = 3,	/* CHAOS			*/
  CLASS_HS  = 4,	/* Hesiod			*/
  CLASS_max
};

enum dns_op
{
  OP_min    = 0,
  OP_QUERY  = 0,
  OP_IQUERY = 1,
  OP_STATUS = 2,
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
  RCODE_BAD_LENGTH,
  RCODE_UNKNOWN_OPTIONS,
  RCODE_A_BAD_ADDR,
  RCODE_NS_BAD_DOMAIN,
  RCODE_MB_BAD_DOMAIN,
  RCODE_MD_BAD_DOMAIN,
  RCODE_MF_BAD_DOMAIN,
  RCODE_MR_BAD_DOMAIN,
  RCODE_MG_BAD_DOMAIN,
  RCODE_MX_BAD_RECORD,
  RCODE_CNAME_BAD_DOMAIN,
  RCODE_HINFO_BAD_RECORD,
  RCODE_MINFO_BAD_RBOX,
  RCODE_MINFO_BAD_EBOX,
  RCODE_FORMAT_STRING,
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

typedef union dns_answer_t
{
  dns_generic_t generic;
  dns_mx_t      mx;
  dns_a_t       a;
  dns_cname_t   cname;
  dns_ns_t      ns;
  dns_txt_t     txt;
  dns_mb_t      mb;
  dns_md_t      md;
  dns_mf_t      mf;
  dns_mg_t      mg;
  dns_hinfo_t   hinfo;
  dns_minfo_t   minfo;
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

extern const char *const c_dns_type_names  [];
extern const char *const c_dns_class_names [];
extern const char *const c_dns_op_names    [];
extern const char *const c_dns_result_names[];

int	dns_encode	(
			  uint8_t           *restrict,
			  size_t            *restrict,
			  const dns_query_t *const restrict
			) __attribute__ ((nonnull));

int	dns_decode	(
			  dns_query_t *restrict,
			  const uint8_t *const restrict,
			  const size_t
			) __attribute__ ((nonnull(1,2)));

#endif
