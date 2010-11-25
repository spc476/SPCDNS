
#ifndef DNS_H
#define DNS_H

#define MAX_DNS_QUERY_SIZE	512
#define MAX_DOMAIN_SEGMENT	 64
#define MAX_STRING_LEN		256

enum dns_type
{
  RR_A        =  1,	/* IPv4 Address 		*/ /* RFC-1035 */
  RR_NS       =  2,	/* Name server			*/
  RR_MD       =  3,	/* Mail Destination (obsolete)	*/
  RR_MF       =  4,	/* Mail Forwarder (obsolete)	*/
  RR_CNAME    =  5,	/* Canonical name		*/
  RR_SOA      =  6,	/* Start of Authority		*/
  RR_MB       =  7,	/* Mailbox (experimental)	*/
  RR_MG       =  8,	/* Mailgroup (experimental)	*/
  RR_MR       =  9,	/* Mailrename (experimental)	*/
  RR_NULL     = 10,	/* NULL resource (experimental)	*/
  RR_WKS      = 11,	/* Well Known Service		*/
  RR_PTR      = 12,	/* Pointer			*/
  RR_HINFO    = 13,	/* Host Info			*/
  RR_MINFO    = 14,	/* Mailbox/mail list info	*/
  RR_MX       = 15,	/* Mail Exchange		*/
  RR_TXT      = 16,	/* Text				*/
  RR_RP       = 17,	/* Responsible Person		*/ /* RFC-1183 */
  RR_AFSDB    = 18,	/* Andrew File System DB	*/
  RR_X25      = 19,	/* X.25 address, route binding  */
  RR_ISDN     = 20,	/* ISDN address, route binding	*/
  RR_RT       = 21,	/* Route Through		*/
  RR_NSAP     = 22,	/* Network Service Access Proto	*/ /* RFC-1348 */
  RR_NSAP_PTR = 23,	/* NSAP Pointer			*/
  RR_SIG      = 24,	/* Signature			*/ /* RFC-2065 */  
  RR_KEY      = 25,	/* Key				*/
  RR_AAAA     = 28,	/* IPv6 Address			*/ /* RFC-1886 */
  RR_LOC      = 29,	/* Location			*/ /* RFC-1876 */
  RR_NXT      = 30,	/* Next RR			*/ /* RFC-2065 */
  RR_SRV      = 33,	/* Service			*/ /* RFC-2782 */
  RR_NAPTR    = 35,	/* Naming Authority Pointer	*/ /* RFC-2915 */
  RR_A6       = 38,	/* IPv6 Address			*/ /* RFC-2874 */
  RR_APL      = 42,	/* Address Prefix List		*/ /* RFC-3123 */
  RR_DS       = 43,	/* Delegation Signer		*/ /* RFC-3658 */  
  RR_RRSIG    = 46,	/* Resource Record Signature	*/ /* RFC-4034 */
  RR_NSEC     = 47,	/* Next Security Record		*/
  RR_DNSKEY   = 48,	/* DNS Security	Key		*/

	/* Query types, >= 128 */
  
  RR_TSIG     = 250,	/* Transaction Signature	*/ /* RFC-2845 */
  RR_AXFR     = 252,	/* Transfer of zone		*/ /* RFC-1035 */
  RR_MAILB    = 253,	/* Mailbox related records	*/
  RR_MAILA    = 254,	/* Mail agent RRs (obsolete)	*/
  RR_ANY      = 255,	/* All records			*/
};

enum dns_class
{
  CLASS_IN  = 1,	/* Internet			*/
  CLASS_CS,		/* CSNET - obsolete		*/
  CLASS_CH,		/* CHAOS			*/
  CLASS_HS,		/* Hesiod			*/
  CLASS_NONE = 254,	/* 				*/ /* RFC-2136 */
};

enum dns_op
{
  OP_QUERY  = 0,	/* RFC-1035 */
  OP_IQUERY = 1,	/* obsolete */	/* RFC-3425 */
  OP_STATUS = 2,	/* RFC-1035 */  
  OP_NOTIFY = 4,	/* RFC-1996 */
  OP_UPDATE = 5		/* RFC-2136 */  
};

enum dns_rcode
{
  RCODE_OKAY = 0,		/* RFC-1035 */
  RCODE_FORMAT_ERROR,
  RCODE_SERVER_FAILURE,
  RCODE_NAME_ERROR,
  RCODE_NOT_IMPLEMENTED,
  RCODE_REFUSED,
  RCODE_YXDOMAIN,		/* RFC-2136 */
  RCODE_YXRRSET,
  RCODE_NXRRSET,
  RCODE_NOTAUTH,
  RCODE_NOTZONE,
  RCODE_BADVERS = 16,		/* RFC-2671 */
  RCODE_BADSIG  = 16,		/* RFC-2845 */
  RCODE_BADKEY,
  RCODE_BADTIME,
  RCODE_BADNAME,		/* RFC-2930 */
  RCODE_BADALG,
  RCODE_BADTRUC,		/* RFC-4635 */
  
  RCODE_PRIVATE      = 3841,
  RCODE_DOMAIN_ERROR = 3841,
  RCODE_DOMAIN_LOOP,
  RCODE_QUESTION_BAD,
  RCODE_MX_BAD_RECORD,
  RCODE_ANSWER_BAD,
  RCODE_BAD_LENGTH,
  RCODE_A_BAD_ADDR,
  RCODE_SOA_BAD_LEN,
  RCODE_UNKNOWN_OPTIONS,
  RCODE_NO_MEMORY,
  
};  

enum edns0_label
{
  EDNS0_ELT = 1,	/* RFC-2673 */
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

typedef struct dns_afsdb_t	/* RFC-1183 */
{
  const char     *name;
  enum dns_type   type;
  enum dns_class  class;
  TTL             ttl;
  int             subtype;
  const char     *hostname;
} dns_afsdb_t;

typedef struct dns_rp_t
{
  const char     *name;
  enum dns_type   type;
  enum dns_class  class;
  TTL             ttl;
  const char     *mbox;
  const char     *domain;
} dns_rp_t;

typedef struct dns_x25_t
{
  const char     *name;
  enum dns_type   type;
  enum dns_class  class;
  TTL             ttl;
  const char     *psdnaddress;
} dns_x25_t;

typedef struct dns_isdn_t
{
  const char     *name;
  enum dns_type   type;
  enum dns_class  class;
  TTL             ttl;
  const char     *isdnaddress;
  const char     *sa;
} dns_isdn_t;

typedef struct dns_rt_t
{
  const char     *name;
  enum dns_type   type;
  enum dns_class  class;
  TTL             ttl;
  int             preference;
  const char     *host;
} dns_rt_t;

typedef struct dns_nsap_t	/* RFC-1348 */
{
  const char     *name;
  enum dns_type   type;
  enum dns_class  class;
  TTL             ttl;
  const char     *length;
  const char     *nsapaddress;
} dns_nsap_t;

typedef struct dns_nsap_ptr_t
{
  const char     *name;
  enum dns_type   type;
  enum dns_class  class;
  TTL             ttl;
  const char     *owner;
} dns_nsap_ptr_t;

struct dnsloc_long;

typedef struct dns_loc_t	/* RFC-1876 */
{
  const char     *name;
  enum dns_type   type;
  enum dns_class  class;
  TTL             ttl;
  int             version;
  unsigned long   size;		/* plese see RFC-1876 for a discussion 	*/
  unsigned long   horiz_pre;	/* of these fields			*/
  unsigned long   vert_pre;
  int             lat;
  int             lat_min;
  int             lat_sec;
  int             lng;
  int             lng_min;
  int             lng_sec;
  long            altitude;
} dns_loc_t;  

typedef struct dns_aaaa_t	/* RFC-1886 */
{
  const char      *name;
  enum dns_type    type;
  enum dns_class   class;
  TTL              ttl;
  struct in6_addr  ipv6;
} dns_aaaa_t;

enum dnskey_algorithm		/* RFC-2065 */
{
  DNSKEYA_RSAMD5     =   1,
  DNSKEYA_DH         =   2,	/* RFC-2535 */
  DNSKEYA_DSA        =   3,	/* RFC-2535 */
  DNSKEYA_ECC        =   4,	/* RFC-2535 */
  DNSKEYA_RSASHA1    =   5,	/* RFC-3110 */
  DNSKEYA_INDIRECT   = 252,	/* RFC-2535 */
  DNSKEYA_PRIVATEDNS = 253,
  DNSKEYA_PRIVATEOID = 254,
  DNSKEYA_RSVP       = 255
};

enum dnskey_protocol		/* RFC-2535 */
{
  DNSKEYP_NONE   =   0,
  DNSKEYP_TLS    =   1,
  DNSKEYP_EMAIL  =   2,
  DNSKEYP_DNSSEC =   3,
  DNSKEYP_IPSEC  =   4,
  DNSKEYP_ALL    = 255
};

typedef union dnskey_key
{
  struct
  {
    size_t   expsize;
    uint8_t *exponent;
    size_t   modsize;
    uint8_t *modulus;
  } md5;

  struct
  {
    size_t   size;
    uint8_t *data;
  } unknown;
} dnskey_key;

typedef struct dns_key_t
{
  const char     *name;
  enum dns_type   type;
  enum dns_class  class;
  TTL             ttl;
  struct
  {
    bool authentication;
    bool confidential;
    bool experimental;
    bool user;
    bool zone;
    bool host;
    bool ipsec;
    bool email;		/* not in RFC-2535 */
  }                      flags;
  int                    signatory;
  enum dnskey_protocol   protocol;
  enum dnskey_algorithm  algorithm;
  dnskey_key             key;
} dns_key_t;

typedef struct dns_sig_t
{
  const char            *name;
  enum dns_type          type;
  enum dns_class         class;
  TTL                    ttl;
  enum dns_type          covered;
  enum dnskey_algorithm  algorithm;
  int                    labels;
  TTL                    originttl;
  unsigned long          sigexpire;
  unsigned long          timesigned;
  uint16_t               keyfootprint;
  const char            *signer;
  size_t                 sigsize;
  uint8_t               *signature;
} dns_sig_t;

typedef struct dns_nxt_t
{
  const char     *name;
  enum dns_type   type;
  enum dns_class  class;
  TTL             ttl;
  const char     *next;
  size_t          numbits;
  uint8_t        *bitmap;
} dns_nxt_t;
  
typedef struct dns_srv_t	/* RFC-2782 */
{
  const char     *name;
  enum dns_type   type;
  enum dns_class  class;
  TTL             ttl;
  int             priority;
  int             weight;
  int             port;
  const char     *target;
} dns_srv_t;

typedef struct dns_tsig_t	/* RFC-2845 */
{
  const char     *name;
  enum dns_type   type;
  enum dns_class  class;
  TTL             ttl;	/* must be 0 */
  const char     *algorithm;
  uint64_t        timesigned;
  unsigned int    fudge;
  size_t          MACsize;
  uint8_t        *MAC;
  int             id;
  int             error;
  size_t          lenother;
  uint8_t        *other;
} dns_tsig_t;

typedef struct dns_a6_t		/* RFC-2874 */
{
  const char     *name;
  enum dns_type   type;
  enum dns_class  class;
  TTL             ttl;
  uint8_t         address[16];
  const char     *prefixname;
} dns_a6_6;

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

typedef struct dnsapl_record
{
  int      addressfamily;
  int      prefix;
  size_t   afdlength;
  uint8_t *afdpart;
  bool     negate;
} dnsapl_record;

typedef struct dns_apl_t	/* RFC-3123 */
{
  const char     *name;
  enum dns_type   type;
  enum dns_class  class;
  TTL             ttl;
  size_t          numrecs;
  dnsapl_record  *recs;
} dns_apl_t;

enum dnsds_digest		/* RFC-3658 */
{
  DNSDS_SHA1 = 1,
};

typedef struct dns_ds_t
{
  const char            *name;
  enum dns_type          type;
  enum dns_class         class;
  TTL                    ttl;
  enum dnskey_protocol   keytag;
  enum dnskey_algorithm  algorithm;
  enum dnsds_digest      digest;
  size_t                 digestlen;
  uint8_t               *digestdata;
} dns_ds_t;

typedef struct dns_dnskey_t	/* RFC-4034 */
{
  const char           *name;
  enum dns_type         type;
  enum dns_class        class;
  TTL                   ttl;
  bool                  zonekey;
  bool                  sep;
  enum dnskey_protocol  protocol;	/* must be DNSKEYP_DNSSEC */
  enum dnskey_algorithm algoritm;
  size_t                keysize;
  uint8_t              *key;
} dns_dnskey_t;  

typedef struct dns_rrsig_t
{
  const char            *name;
  enum dns_type          type;
  enum dns_class         class;
  TTL                    ttl;
  enum dns_type          covered;
  enum dnskey_algorithm  algorithm;
  int                    labels;
  TTL                    originttl;
  unsigned long          sigexpire;
  unsigned long          timesigned;
  uint16_t               keyfootprint;
  const char            *signer;
  size_t                 sigsize;
  uint8_t               *signature;
} dns_rrsig_t;

typedef struct dns_nsec_t
{
  const char     *name;
  enum dns_type   type;
  enum dns_class  class;
  TTL             ttl;
  const char     *next;
  size_t          numbits;
  uint8_t        *bitmap;
} dns_nsec_t;

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
  dns_rp_t      rp;
  dns_afsdb_t   fsdb;
  dns_x25_t     x25;
  dns_isdn_t    isdn;
  dns_rt_t      rt;
  dns_naptr_t   naptr;
  dns_aaaa_t    aaaa;
  dns_srv_t     srv;
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
  bool            ad;		/* RFC-2065 */
  bool            cd;		/* RFC-2065 */
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
