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

#ifndef DNS_H
#define DNS_H

#ifdef __cplusplus
  extern "C" {
#endif

#ifndef __GNUC__
#  define __attribute__ (x)
#endif

#define MAX_DNS_QUERY_SIZE	512
#define MAX_DOMAIN_SEGMENT	 64
#define MAX_STRING_LEN		256

typedef enum dns_type
{
  RR_A        =  1,	/* IPv4 Address 		*/ /* RFC-1035 */
  RR_NS       =  2,	/* Name server			*/ /* RFC-1035 */
  RR_MD       =  3,	/* Mail Destination (obsolete)	*/ /* RFC-1035 */
  RR_MF       =  4,	/* Mail Forwarder (obsolete)	*/ /* RFC-1035 */
  RR_CNAME    =  5,	/* Canonical name		*/ /* RFC-1035 */
  RR_SOA      =  6,	/* Start of Authority		*/ /* RFC-1035 */
  RR_MB       =  7,	/* Mailbox (experimental)	*/ /* RFC-1035 */
  RR_MG       =  8,	/* Mailgroup (experimental)	*/ /* RFC-1035 */
  RR_MR       =  9,	/* Mailrename (experimental)	*/ /* RFC-1035 */
  RR_NULL     = 10,	/* NULL resource (experimental)	*/ /* RFC-1035 */
  RR_WKS      = 11,	/* Well Known Service		*/ /* RFC-1035 */
  RR_PTR      = 12,	/* Pointer			*/ /* RFC-1035 */
  RR_HINFO    = 13,	/* Host Info			*/ /* RFC-1035 */
  RR_MINFO    = 14,	/* Mailbox/mail list info	*/ /* RFC-1035 */
  RR_MX       = 15,	/* Mail Exchange		*/ /* RFC-1035 */
  RR_TXT      = 16,	/* Text				*/ /* RFC-1035 */
  RR_RP       = 17,	/* Responsible Person		*/ /* RFC-1183 */
  RR_AFSDB    = 18,	/* Andrew File System DB	*/ /* RFC-1183 */
  RR_X25      = 19,	/* X.25 address, route binding  */ /* RFC-1183 */
  RR_ISDN     = 20,	/* ISDN address, route binding	*/ /* RFC-1183 */
  RR_RT       = 21,	/* Route Through		*/ /* RFC-1183 */
  RR_NSAP     = 22,	/* Network Service Access Proto	*/ /* RFC-1348 */
  RR_NSAP_PTR = 23,	/* NSAP Pointer			*/ /* RFC-1348 */
  RR_SIG      = 24,	/* Signature			*/ /* RFC-2065 */  
  RR_KEY      = 25,	/* Key				*/ /* RFC-2065 */
  RR_PX       = 26,	/* X.400 mail mapping		*/ /* RFC-2163 */
  RR_GPOS     = 27,	/* Geographical position (obs)	*/ /* RFC-1712 */
  RR_AAAA     = 28,	/* IPv6 Address			*/ /* RFC-1886 */
  RR_LOC      = 29,	/* Location			*/ /* RFC-1876 */
  RR_NXT      = 30,	/* Next RR			*/ /* RFC-2065 */
  RR_EID      = 31,	/* Endpoint Identifier		*/ /* ???      */
  RR_NIMLOC   = 32,	/* Nimrod Locator		*/ /* ???      */
  RR_SRV      = 33,	/* Service			*/ /* RFC-2782 */
  RR_ATM      = 34,	/* ATM Address			*/ /* ???      */
  RR_NAPTR    = 35,	/* Naming Authority Pointer	*/ /* RFC-2915 */
  RR_KX       = 36,	/* Key Exchange			*/ /* ???      */
  RR_CERT     = 37,	/* Certification		*/ /* ???      */
  RR_A6       = 38,	/* IPv6 Address			*/ /* RFC-2874 */
  RR_DNAME    = 39,	/* Non-terminal DNAME (IPv6)	*/ /* RFC-2672 */
  RR_SINK     = 40,	/* Kitchen sink (experiemental) */ /* ???      */
  RR_OPT      = 41,	/* EDNS0 option (meta-RR)	*/ /* RFC-2673 */
  RR_APL      = 42,	/* Address Prefix List		*/ /* RFC-3123 */
  RR_DS       = 43,	/* Delegation Signer		*/ /* RFC-3658 */  
  RR_RRSIG    = 46,	/* Resource Record Signature	*/ /* RFC-4034 */
  RR_NSEC     = 47,	/* Next Security Record		*/ /* RFC-4034 */
  RR_DNSKEY   = 48,	/* DNS Security	Key		*/ /* RFC-4034 */
  RR_SPF      = 99,	/* Sender Policy Framework	*/ /* RFC-4408 */

	/* Query types, >= 128 */
  
  RR_TSIG     = 250,	/* Transaction Signature	*/ /* RFC-2845 */
  RR_IXFR     = 251,	/* Incremental zone transfer	*/ /* ???      */
  RR_AXFR     = 252,	/* Transfer of zone		*/ /* RFC-1035 */
  RR_MAILB    = 253,	/* Mailbox related records	*/ /* RFC-1035 */
  RR_MAILA    = 254,	/* Mail agent RRs (obsolete)	*/ /* RFC-1035 */
  RR_ANY      = 255,	/* All records			*/ /* RFC-1035 */
} dns_type_t;

typedef enum dns_class
{
  CLASS_IN   =   1,	/* Internet		*/ /* RFC-1035 */
  CLASS_CS   =   2,	/* CSNET - obsolete	*/ /* RFC-1035 */
  CLASS_CH   =   3,	/* CHAOS		*/ /* RFC-1035 */
  CLASS_HS   =   4,	/* Hesiod		*/ /* RFC-1035 */
  CLASS_NONE = 254,	/* 			*/ /* RFC-2136 */
} dns_class_t;

typedef enum dns_op
{
  OP_QUERY  = 0,	/* RFC-1035 */
  OP_IQUERY = 1,	/* obsolete */	/* RFC-3425 */
  OP_STATUS = 2,	/* RFC-1035 */  
  OP_NOTIFY = 4,	/* RFC-1996 */
  OP_UPDATE = 5		/* RFC-2136 */  
} dns_op_t;

typedef enum dns_rcode
{
  RCODE_OKAY            =    0,	/* RFC-1035 */
  RCODE_FORMAT_ERROR    =    1,	/* RFC-1035 */
  RCODE_SERVER_FAILURE  =    2,	/* RFC-1035 */
  RCODE_NAME_ERROR      =    3,	/* RFC-1035 */
  RCODE_NOT_IMPLEMENTED =    4,	/* RFC-1035 */
  RCODE_REFUSED         =    5,	/* RFC-1035 */
  RCODE_YXDOMAIN        =    6,	/* RFC-2136 */
  RCODE_YXRRSET         =    7,	/* RFC-2136 */
  RCODE_NXRRSET         =    8,	/* RFC-2136 */
  RCODE_NOTAUTH         =    9,	/* RFC-2136 */
  RCODE_NOTZONE         =   10,	/* RFC-2136 */
  RCODE_BADVERS         =   16,	/* RFC-2671 */
  RCODE_BADSIG          =   16,	/* RFC-2845 */
  RCODE_BADKEY          =   17,	/* RFC-2845 */
  RCODE_BADTIME         =   18,	/* RFC-2845 */
  RCODE_BADMODE         =   19,	/* RFC-2845 */
  RCODE_BADNAME         =   20,	/* RFC-2930 */
  RCODE_BADALG          =   21,	/* RFC-2930 */
  RCODE_BADTRUC         =   22,	/* RFC-4635 */  
  RCODE_PRIVATE         = 3841,	/* RFC-2929 */
  
  RCODE_NO_MEMORY
} dns_rcode_t;

typedef enum edns0_label	/* RFC-2673 */
{
  EDNS0_ELT = 1,		
} ends0_label_t;

typedef uint32_t TTL;

typedef struct dns_question_t	/* RFC-1035 */
{
  const char  *name;
  dns_type_t   type;
  dns_class_t  class;
} dns_question_t;

typedef struct dns_generic_t	/* RFC-1035 */
{
  const char  *name;
  dns_type_t   type;
  dns_class_t  class;
  TTL          ttl;
} dns_generic_t;

typedef struct dns_a_t		/* RFC-1035 */
{
  const char  *name;
  dns_type_t   type;
  dns_class_t  class;
  TTL          ttl;
  in_addr_t    address;
} dns_a_t;

typedef struct dns_ns_t		/* RFC-1035 */
{
  const char  *name;
  dns_type_t   type;
  dns_class_t  class;
  TTL          ttl;
  const char  *nsdname;
} dns_ns_t;

typedef struct dns_md_t		/* RFC-1035 */
{
  const char  *name;
  dns_type_t   type;
  dns_class_t  class;
  TTL          ttl;
  const char  *madname;
} dns_md_t;

typedef struct dns_mf_t		/* RFC-1035 */
{
  const char  *name;
  dns_type_t   type;
  dns_class_t  class;
  TTL          ttl;
  const char  *madname;
} dns_mf_t;

typedef struct dns_cname_t	/* RFC-1035 */
{
  const char  *name;
  dns_type_t   type;
  dns_class_t  class;
  TTL          ttl;
  const char  *cname;
} dns_cname_t;

typedef struct dns_soa_t	/* RFC-1035 */
{
  const char  *name;
  dns_type_t   type;
  dns_class_t  class;
  TTL          ttl;
  const char  *mname;
  const char  *rname;
  uint32_t     serial;
  uint32_t     refresh;
  uint32_t     retry;
  uint32_t     expire;
  uint32_t     minimum;
} dns_soa_t;

typedef struct dns_mb_t		/* RFC-1035 */
{
  const char  *name;
  dns_type_t   type;
  dns_class_t  class;
  TTL          ttl;
  const char  *madname;
} dns_mb_t;

typedef struct dns_mg_t		/* RFC-1035 */
{
  const char  *name;
  dns_type_t   type;
  dns_class_t  class;
  TTL          ttl;
  const char  *mgmname;
} dns_mg_t;

typedef struct dns_mr_t		/* RFC-1035 */
{
  const char  *name;
  dns_type_t   type;
  dns_class_t  class;
  TTL          ttl;
  const char  *newname;
} dns_mr_t;

typedef struct dns_null_t	/* RFC-1035 */
{
  const char  *name;
  dns_type_t   type;
  dns_class_t  class;
  TTL          ttl;
  size_t       size;
  uint8_t     *data;
} dns_null_t;

typedef struct dns_wks_t	/* RFC-1035 */
{
  const char  *name;
  dns_type_t   type;
  dns_class_t  class;
  TTL          ttl;
  in_addr_t    address;
  int          protocol;
  size_t       numbits;
  uint8_t     *bits;
} dns_wks_t;

typedef struct dns_ptr_t	/* RFC-1035 */
{
  const char  *name;
  dns_type_t   type;
  dns_class_t  class;
  TTL          ttl;
  const char  *ptr;
} dns_ptr_t;

typedef struct dns_hinfo_t	/* RFC-1035 */
{
  const char  *name;
  dns_type_t   type;
  dns_class_t  class;
  TTL          ttl;
  const char  *cpu;
  const char  *os;
} dns_hinfo_t;

typedef struct dns_minfo_t	/* RFC-1035 */
{
  const char  *name;
  dns_type_t   type;
  dns_class_t  class;
  TTL          ttl;
  const char  *rmailbx;
  const char  *emailbx;
} dns_minfo_t;

typedef struct dns_mx_t		/* RFC-1035 */
{
  const char  *name;
  dns_type_t   type;
  dns_class_t  class;
  TTL          ttl;
  int          preference;
  const char  *exchange;
} dns_mx_t;

typedef struct dns_txt_t	/* RFC-1035 */
{
  const char  *name;
  dns_type_t   type;
  dns_class_t  class;
  TTL          ttl;
  size_t       len;
  const char  *text;
} dns_txt_t;

typedef struct dns_rp_t		/* RFC-1183 */
{
  const char  *name;
  dns_type_t   type;
  dns_class_t  class;
  TTL          ttl;
  const char  *mbox;
  const char  *domain;
} dns_rp_t;

typedef struct dns_afsdb_t	/* RFC-1183 */
{
  const char  *name;
  dns_type_t   type;
  dns_class_t  class;
  TTL          ttl;
  int          subtype;
  const char  *hostname;
} dns_afsdb_t;

typedef struct dns_x25_t	/* RFC-1183 */
{
  const char  *name;
  dns_type_t   type;
  dns_class_t  class;
  TTL          ttl;
  size_t       size;
  const char  *psdnaddress;
} dns_x25_t;

typedef struct dns_isdn_t	/* RFC-1183 */
{
  const char  *name;
  dns_type_t   type;
  dns_class_t  class;
  TTL          ttl;
  const char  *isdnaddress;
  const char  *sa;
} dns_isdn_t;

typedef struct dns_rt_t		/* RFC-1183 */
{
  const char  *name;
  dns_type_t   type;
  dns_class_t  class;
  TTL          ttl;
  int          preference;
  const char  *host;
} dns_rt_t;

typedef struct dns_nsap_t	/* RFC-1348 */
{
  const char  *name;
  dns_type_t   type;
  dns_class_t  class;
  TTL          ttl;
  const char  *length;
  const char  *nsapaddress;
} dns_nsap_t;

typedef struct dns_nsap_ptr_t	/* RFC-1348 */
{
  const char  *name;
  dns_type_t   type;
  dns_class_t  class;
  TTL          ttl;
  const char  *owner;
} dns_nsap_ptr_t;

typedef enum dnskey_algorithm	/* RFC-2065 */
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
} dnskey_algorithm;

typedef struct dns_sig_t	/* RFC-2065 */
{
  const char       *name;
  dns_type_t        type;
  dns_class_t       class;
  TTL               ttl;
  dns_type_t        covered;
  dnskey_algorithm  algorithm;
  int               labels;
  TTL               originttl;
  unsigned long     sigexpire;
  unsigned long     timesigned;
  uint16_t          keyfootprint;
  const char       *signer;
  size_t            sigsize;
  uint8_t          *signature;
} dns_sig_t;

typedef enum dnskey_protocol	/* RFC-2535 */
{
  DNSKEYP_NONE   =   0,
  DNSKEYP_TLS    =   1,
  DNSKEYP_EMAIL  =   2,
  DNSKEYP_DNSSEC =   3,
  DNSKEYP_IPSEC  =   4,
  DNSKEYP_ALL    = 255
} dnskey_protocol;

typedef union dnskey_key	/* RFC-2065 */
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

typedef struct dns_key_t	/* RFC-2065 */
{
  const char  *name;
  dns_type_t   type;
  dns_class_t  class;
  TTL          ttl;
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
  }                 flags;
  int               signatory;
  dnskey_protocol   protocol;
  dnskey_algorithm  algorithm;
  dnskey_key        key;
} dns_key_t;

typedef struct dns_px_t		/* RFC-2163 */
{
  const char  *name;
  dns_type_t   type;
  dns_class_t  class;
  TTL          ttl;
  const char  *map822;
  const char  *mapx400;
} dns_px_t;

typedef struct dns_gpos_t	/* RFC-1712 */
{
  const char  *name;
  dns_type_t   type;
  dns_class_t  class;
  TTL          ttl;
  double       longitude;
  double       latitude;
  double       altitude;
} dns_gpos_t;

typedef struct dns_aaaa_t	/* RFC-1886 */
{
  const char      *name;
  dns_type_t       type;
  dns_class_t      class;
  TTL              ttl;
  struct in6_addr  address;
} dns_aaaa_t;

typedef struct dnsloc_angle	/* RFC-1876 */
{
  int  deg;
  int  min;
  int  sec;
  int  frac;
  bool nw;	/* Northern or Western Hemisphere */
} dnsloc_angle;

typedef struct dns_loc_t	/* RFC-1876 */
{
  const char     *name;
  dns_type_t      type;
  dns_class_t     class;
  TTL             ttl;
  int             version;
  unsigned long   size;		/* plese see RFC-1876 for a discussion 	*/
  unsigned long   horiz_pre;	/* of these fields			*/
  unsigned long   vert_pre;
  dnsloc_angle    latitude;
  dnsloc_angle    longitude;
  long            altitude;
} dns_loc_t;  

typedef struct dns_nxt_t	/* RFC-2065 */
{
  const char  *name;
  dns_type_t   type;
  dns_class_t  class;
  TTL          ttl;
  const char  *next;
  size_t       numbits;
  uint8_t     *bitmap;
} dns_nxt_t;

typedef struct dns_eid_t	/* (unknown) */
{
  const char  *name;
  dns_type_t   type;
  dns_class_t  class;
  TTL          ttl;
  size_t       size;
  uint8_t     *rawdata;
} dns_eid_t;

typedef struct dns_nimloc_t	/* (unknown) */
{
  const char  *name;
  dns_type_t   type;
  dns_class_t  class;
  TTL          ttl;
  size_t       size;
  uint8_t     *rawdata;
} dns_nimloc_t;

typedef struct dns_srv_t	/* RFC-2782 */
{
  const char  *name;
  dns_type_t   type;
  dns_class_t  class;
  TTL          ttl;
  int          priority;
  int          weight;
  int          port;
  const char  *target;
} dns_srv_t;

typedef struct dns_atm_t	/* (unknown) */
{
  const char  *name;
  dns_type_t   type;
  dns_class_t  class;
  TTL          ttl;
  size_t       size;
  uint8_t     *rawdata;
} dns_atm_t;

typedef struct dns_naptr_t	/* RFC-2915 */
{
  const char  *name;
  dns_type_t   type;
  dns_class_t  class;
  TTL          ttl;
  int          order;
  int          preference;
  const char  *flags;
  const char  *services;
  const char  *regexp;
  const char  *replacement;
} dns_naptr_t;

typedef struct dns_kx_t		/* (unknown) */
{
  const char  *name;
  dns_type_t   type;
  dns_class_t  class;
  TTL          ttl;
  size_t       size;
  uint8_t     *rawdata;
} dns_kx_t;

typedef struct dns_cert_t	/* (unknown) */
{
  const char  *name;
  dns_type_t   type;
  dns_class_t  class;
  TTL          ttl;
  size_t       size;
  uint8_t     *rawdata;
} dns_cert_t;

typedef struct dns_a6_t		/* RFC-2874 */
{
  const char  *name;
  dns_type_t   type;
  dns_class_t  class;
  TTL          ttl;
  uint8_t      address[16];
  const char  *prefixname;
} dns_a6_t;

typedef struct dns_dname_t	/* RFC-2672 */
{
  const char  *name;
  dns_type_t   type;
  dns_class_t  class;
  TTL          ttl;
  size_t       size;
  uint8_t     *rawdata;
} dns_dname_t;

typedef struct dns_sink_t	/* (unknown) */
{
  const char  *name;
  dns_type_t   type;
  dns_class_t  class;
  TTL          ttl;
  size_t       size;
  uint8_t     *rawdata;
} dns_sink_t;

typedef struct dns_eds0opt_t	/* RFC-2673 */
{
  const char  *name;
  dns_type_t   type;
  dns_class_t  class;
  TTL          ttl;
  size_t       size;
  uint8_t     *rawdata;
} dns_edns0opt_t;

typedef struct dnsapl_record	/* RFC-3123 */
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
  dns_type_t      type;
  dns_class_t     class;
  TTL             ttl;
  size_t          numrecs;
  dnsapl_record  *recs;
} dns_apl_t;


typedef enum dnsds_digest	/* RFC-3658 */
{
  DNSDS_SHA1 = 1,
} dnsds_digest;

typedef struct dns_ds_t		/* RFC-3658 */
{
  const char       *name;
  dns_type_t        type;
  dns_class_t       class;
  TTL               ttl;
  dnskey_protocol   keytag;
  dnskey_algorithm  algorithm;
  dnsds_digest      digest;
  size_t            digestlen;
  uint8_t          *digestdata;
} dns_ds_t;

typedef struct dns_rrsig_t	/* RFC-4034 */
{
  const char       *name;
  dns_type_t        type;
  dns_class_t       class;
  TTL               ttl;
  dns_type_t        covered;
  dnskey_algorithm  algorithm;
  int               labels;
  TTL               originttl;
  unsigned long     sigexpire;
  unsigned long     timesigned;
  uint16_t          keyfootprint;
  const char       *signer;
  size_t            sigsize;
  uint8_t          *signature;
} dns_rrsig_t;

typedef struct dns_nsec_t	/* RFC-4034 */
{
  const char  *name;
  dns_type_t   type;
  dns_class_t  class;
  TTL          ttl;
  const char  *next;
  size_t       numbits;
  uint8_t     *bitmap;
} dns_nsec_t;

typedef struct dns_dnskey_t	/* RFC-4034 */
{
  const char       *name;
  dns_type_t        type;
  dns_class_t       class;
  TTL               ttl;
  bool              zonekey;
  bool              sep;
  dnskey_protocol   protocol;	/* must be DNSKEYP_DNSSEC */
  dnskey_algorithm  algoritm;
  size_t            keysize;
  uint8_t          *key;
} dns_dnskey_t;  

typedef struct dns_spf_t	/* RFC-4408 */
{
  const char  *name;
  dns_type_t   type;
  dns_class_t  class;
  TTL          ttl;
  size_t       len;
  const char  *text;
} dns_spf_t;

typedef struct dns_tsig_t	/* RFC-2845 */
{
  const char   *name;
  dns_type_t    type;
  dns_class_t   class;
  TTL           ttl;	/* must be 0 */
  const char   *algorithm;
  uint64_t      timesigned;
  unsigned int  fudge;
  size_t        MACsize;
  uint8_t      *MAC;
  int           id;
  int           error;
  size_t        lenother;
  uint8_t      *other;
} dns_tsig_t;

typedef struct dns_x_t		/* CATCH-ALL */
{
  const char  *name;
  dns_type_t   type;
  dns_class_t  class;
  TTL          ttl;
  size_t       size;
  uint8_t     *rawdata;
} dns_x_t;

typedef union dns_answer_t
{
  dns_generic_t  generic;
  dns_x_t        x;
  dns_a_t        a;
  dns_ns_t       ns;
  dns_md_t       md;
  dns_mf_t       mf;
  dns_cname_t    cname;
  dns_soa_t      soa;
  dns_mb_t       mb;
  dns_mg_t       mg;
  dns_mr_t       mr;
  dns_null_t     null;
  dns_wks_t      wks;
  dns_ptr_t      ptr;
  dns_hinfo_t    hinfo;
  dns_minfo_t    minfo;
  dns_mx_t       mx;
  dns_txt_t      txt;
  dns_rp_t       rp;
  dns_afsdb_t    afsdb;
  dns_x25_t      x25;
  dns_isdn_t     isdn;
  dns_rt_t       rt;
  dns_nsap_t     nsap;
  dns_nsap_ptr_t nsap_ptr;
  dns_sig_t      sig;
  dns_key_t      key;
  dns_px_t       px;
  dns_gpos_t     gpos;
  dns_aaaa_t     aaaa;
  dns_loc_t      loc;
  dns_nxt_t      nxt;
  dns_eid_t      eid;
  dns_nimloc_t   nimloc;
  dns_srv_t      srv;
  dns_atm_t      atm;
  dns_naptr_t    naptr;
  dns_kx_t       kx;
  dns_cert_t     cert;
  dns_a6_t       a6;
  dns_dname_t    dname;
  dns_sink_t     sink;
  dns_edns0opt_t opt;
  dns_apl_t      apl;
  dns_ds_t       ds;
  dns_rrsig_t    rrsig;
  dns_nsec_t     nsec;
  dns_dnskey_t   dnskey;
  dns_spf_t      spf;
  dns_tsig_t     tsig;
} dns_answer_t;

typedef struct dns_query_t	/* RFC-1035 */
{
  int             id;
  bool            query;
  dns_op_t          opcode;
  bool            aa;
  bool            tc;
  bool            rd;
  bool            ra;
  bool            ad;		/* RFC-2065 */
  bool            cd;		/* RFC-2065 */
  dns_rcode_t       rcode;
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

dns_rcode_t	dns_encode(
			  uint8_t           *restrict,
			  size_t            *restrict,
			  const dns_query_t *const restrict
			 ) __attribute__ ((nothrow,nonnull));

dns_rcode_t	dns_decode(
                          void *const restrict,
                          const size_t,
			  const uint8_t *const restrict,
			  const size_t
			 ) __attribute__ ((nothrow,nonnull(1,3)));

#ifdef __cpluscplus
  }
#endif
#endif
