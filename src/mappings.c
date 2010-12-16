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

/***********************************************************************
*
* Implementation of mapping values to strings, or strings to values.
*
* This code is written to C99.
*
************************************************************************/

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include "dns.h"
#include "mappings.h"

/************************************************************************
*
* The following structure is used to map values to strings.  The arrays
* defined by this structure *MUST* be sorted by value in ascending order.
*
*************************************************************************/

struct int_string_map
{
  const int         value;
  const char *const text;
};

/*******************************************************************
*
* The following structure is used to map strings to values.  The arrays
* defined by this structure *MUST* be sorted by the strings in ascending
* order.
*
*********************************************************************/

struct string_int_map
{
  const char *const text;
  const int         value;
};

/************************************************************************/

static const struct int_string_map cm_dns_rcode[] =
{
  { RCODE_OKAY 			, "No error"	 			} ,
  { RCODE_FORMAT_ERROR		, "Format error"			} ,
  { RCODE_SERVER_FAILURE 	, "Server failure"			} ,
  { RCODE_NAME_ERROR		, "Non-existant domain"			} ,
  { RCODE_NOT_IMPLEMENTED	, "Not implemented"			} ,
  { RCODE_REFUSED		, "Query refused"			} ,
  { RCODE_YXDOMAIN		, "Name exists when it should not"	} ,
  { RCODE_YXRRSET		, "RRset exists when it should not"	} ,
  { RCODE_NXRRSET		, "RRset does not exist"		} ,
  { RCODE_NOTAUTH		, "Server not authoritative"		} ,
  { RCODE_NOTZONE		, "Zone not in zone section"		} ,
  { RCODE_BADVERS		, "Bad OPT version/TSIG failed"		} ,
  { RCODE_BADKEY		, "Key not recognized"			} ,
  { RCODE_BADTIME		, "Signature out of time window"	} ,
  { RCODE_BADMODE		, "Bad TKEY mode"			} ,
  { RCODE_BADNAME		, "Duplicate key name"			} ,
  { RCODE_BADALG		, "Algorithm not supported"		} ,
  { RCODE_BADTRUC		, "Bad truncation"			} ,
  { RCODE_NO_MEMORY		, "No memory"				} ,
};

#define RCODE_COUNT	(sizeof(cm_dns_rcode) / sizeof(struct int_string_map))

static const struct int_string_map cm_dns_type[] =
{
  { RR_A	, "A"		} ,
  { RR_NS	, "NS"		} ,
  { RR_MD	, "MD"		} ,
  { RR_MF	, "MF"		} ,
  { RR_CNAME	, "CNAME"	} ,
  { RR_SOA	, "SOA"		} ,
  { RR_MB	, "MB"		} ,
  { RR_MG	, "MG"		} ,
  { RR_MR	, "MR"		} ,
  { RR_NULL	, "NULL"	} ,
  { RR_WKS	, "WKS"		} ,
  { RR_PTR	, "PTR"		} ,
  { RR_HINFO	, "HINFO"	} ,
  { RR_MINFO	, "MINFO"	} ,
  { RR_MX	, "MX"		} ,
  { RR_TXT	, "TXT"		} ,
  { RR_RP	, "RP"		} ,
  { RR_AFSDB	, "AFSDB"	} ,
  { RR_X25	, "X25"		} ,
  { RR_ISDN	, "ISDN"	} ,
  { RR_RT	, "RT"		} ,
  { RR_NSAP	, "NSAP"	} ,
  { RR_NSAP_PTR	, "NSAP-PTR"	} ,
  { RR_SIG	, "SIG"		} ,
  { RR_KEY	, "KEY"		} ,
  { RR_PX	, "PX"		} ,
  { RR_GPOS	, "GPOS"	} ,
  { RR_AAAA	, "AAAA"	} ,
  { RR_LOC	, "LOC"		} ,
  { RR_NXT	, "NXT"		} ,
  { RR_EID	, "EID"		} ,
  { RR_NIMLOC	, "NIMLOC"	} ,
  { RR_SRV	, "SRV"		} ,
  { RR_ATM	, "ATM"		} ,
  { RR_NAPTR	, "NAPTR"	} ,
  { RR_KX	, "KX"		} ,
  { RR_CERT	, "CERT"	} ,
  { RR_A6	, "A6"		} ,
  { RR_DNAME	, "DNAME"	} ,
  { RR_SINK	, "SINK"	} ,
  { RR_OPT	, "OPT"		} ,
  { RR_APL	, "APL"		} ,
  { RR_DS	, "DS"		} ,
  { RR_RRSIG	, "RRSIG"	} ,
  { RR_NSEC	, "NSEC"	} ,
  { RR_DNSKEY	, "DNSKEY"	} ,
  { RR_SPF	, "SPF"		} ,
  { RR_TSIG	, "TSIG"	} ,
  { RR_IXFR	, "IXFR"	} ,
  { RR_AXFR	, "AXFR"	} ,
  { RR_MAILB	, "MAILB"	} ,
  { RR_MAILA	, "MAILA"	} ,
  { RR_ANY	, "ANY"		}
};

#define TYPE_COUNT	(sizeof(cm_dns_type) / sizeof(struct int_string_map))

static const struct string_int_map cm_dns_type_is[] =
{
  { "A"		, RR_A		} ,
  { "A6"	, RR_A6		} ,
  { "AAAA"	, RR_AAAA	} ,
  { "AFSDB"	, RR_AFSDB	} ,
  { "ANY"	, RR_ANY	} ,
  { "APL"	, RR_APL	} ,
  { "ATM"	, RR_ATM	} ,
  { "AXFR"	, RR_AXFR	} ,
  { "CERT"	, RR_CERT	} ,
  { "CNAME"	, RR_CNAME	} ,
  { "DNAME"	, RR_DNAME	} ,
  { "DNSKEY"	, RR_DNSKEY	} ,
  { "DS"	, RR_DS		} ,
  { "EID"	, RR_EID	} ,
  { "GPOS"	, RR_GPOS	} ,
  { "HINFO"	, RR_HINFO	} ,
  { "ISDN"	, RR_ISDN	} ,
  { "IXFR"	, RR_IXFR	} ,
  { "KEY"	, RR_KEY	} ,
  { "KX"	, RR_KX		} ,
  { "LOC"	, RR_LOC	} ,
  { "MAILA"	, RR_MAILA	} ,
  { "MAILB"	, RR_MAILB	} ,
  { "MB"	, RR_MB		} ,
  { "MD"	, RR_MD		} ,
  { "MF"	, RR_MF		} ,
  { "MG"	, RR_MG		} ,
  { "MINFO"	, RR_MINFO	} ,
  { "MR"	, RR_MR		} ,
  { "MX"	, RR_MX		} ,
  { "NAPTR"	, RR_NAPTR	} ,
  { "NIMLOC"	, RR_NIMLOC	} ,
  { "NS"	, RR_NS		} ,
  { "NSAP"	, RR_NSAP	} ,
  { "NSAP-PTR"	, RR_NSAP_PTR	} ,
  { "NSEC"	, RR_NSEC	} ,
  { "NULL"	, RR_NULL	} ,
  { "NXT"	, RR_NXT	} ,
  { "OPT"	, RR_OPT	} ,
  { "PTR"	, RR_PTR	} ,
  { "PX"	, RR_PX		} ,
  { "RP"	, RR_RP		} ,
  { "RRSIG"	, RR_RRSIG	} ,
  { "RT"	, RR_RT		} ,
  { "SIG"	, RR_SIG	} ,
  { "SINK"	, RR_SINK	} ,
  { "SOA"	, RR_SOA	} ,
  { "SPF"	, RR_SPF	} ,
  { "SRV"	, RR_SRV	} ,
  { "TSIG"	, RR_TSIG	} ,
  { "TXT"	, RR_TXT	} ,
  { "WKS"	, RR_WKS	} ,
  { "X25"	, RR_X25	} ,
};

static const struct int_string_map cm_dns_class[] =
{
  { CLASS_IN	, "IN"		} ,
  { CLASS_CS	, "CS"		} ,
  { CLASS_CH	, "CH"		} ,
  { CLASS_HS	, "HS"		} ,
  { CLASS_NONE	, "NONE"	} 
};

#define CLASS_COUNT	(sizeof(cm_dns_class) / sizeof(struct int_string_map))

static const struct string_int_map cm_dns_class_is[] =
{
  { "CH"	, CLASS_CH	} ,
  { "CS"	, CLASS_CS	} ,
  { "HS"	, CLASS_HS	} ,
  { "IN"	, CLASS_IN	} ,
  { "NONE"	, CLASS_NONE	} ,
};

static const struct int_string_map cm_dns_op[] = 
{
  { OP_QUERY	, "QUERY"	} ,
  { OP_IQUERY	, "IQUERY"	} ,
  { OP_STATUS	, "STATUS"	} ,
  { OP_NOTIFY	, "NOTIFY"	} ,
  { OP_UPDATE	, "UPDATE"	}
};

#define OP_COUNT	(sizeof(cm_dns_op) / sizeof(struct int_string_map))

static const struct string_int_map cm_dns_op_is[] = 
{
  { "IQUERY"	, OP_IQUERY	} ,
  { "NOTIFY"	, OP_NOTIFY	} ,
  { "QUERY"	, OP_QUERY	} ,
  { "STATUS"	, OP_STATUS	} ,
  { "UPDATE"	, OP_UPDATE	} 
};
 
/*************************************************************************/

static int intstr_cmp(const void *needle,const void *haystack)
{
  const struct int_string_map *pism = haystack;
  const int                   *pi   = needle;

  assert(needle   != NULL);
  assert(haystack != NULL);
  
  return *pi - pism->value;
}

/*********************************************************************/

static int strint_cmp(const void *needle,const void *haystack)
{
  const struct string_int_map *psim = haystack;
  const char                  *key  = needle;
  
  assert(needle   != NULL);
  assert(haystack != NULL);
  
  return strcmp(key,psim->text);
}

/**********************************************************************/

static const char *itosdef(
	int                                         v,
	const struct int_string_map *const restrict pitab,
	const size_t                                itabcnt,
	const char                  *const restrict def
)
{
  struct int_string_map *pism;
  
  assert(v       >= 0);
  assert(pitab   != NULL);
  assert(itabcnt >  0);
  assert(def     != NULL);
  
  pism = bsearch(&v,pitab,itabcnt,sizeof(struct int_string_map),intstr_cmp);
  if (pism)
    return pism->text;
  else
    return def;
}

/********************************************************************/

static int stoidef(
	const char *const restrict                  tag,
	const struct string_int_map *const restrict pstab,
	const size_t                                stabcnt,
	const int                                   def
)
{
  struct string_int_map *psim;
  size_t                 len = strlen(tag) + 1;
  char                   buffer[len];
  
  for (size_t i = 0 ; i < len ; i++)
    buffer[i] = toupper(tag[i]);
  
  psim = bsearch(buffer,pstab,stabcnt,sizeof(struct string_int_map),strint_cmp);
  if (psim)
    return psim->value;
  else
    return def;
}

/*******************************************************************/

const char *dns_rcode_text(const dns_rcode_t r)
{
  return itosdef(r,cm_dns_rcode,RCODE_COUNT,"Unknown error");
}

/*********************************************************************/

const char *dns_type_text(const dns_type_t t)
{
  return itosdef(t,cm_dns_type,TYPE_COUNT,"X-UNKN");
}

/**********************************************************************/

const char *dns_class_text(const dns_class_t c)
{
  return itosdef(c,cm_dns_class,CLASS_COUNT,"X-UNKN");
}

/*******************************************************************/

const char *dns_op_text(const dns_op_t o)
{
  return itosdef(o,cm_dns_op,OP_COUNT,"X-UNKNOWN");
}

/********************************************************************/

dns_type_t dns_type_value(const char *tag)
{
  return stoidef(tag,cm_dns_type_is,TYPE_COUNT,RR_UNKNOWN);
}

/*********************************************************************/

dns_class_t dns_class_value(const char *tag)
{
  return stoidef(tag,cm_dns_class_is,CLASS_COUNT,CLASS_UNKNOWN);
}

/**********************************************************************/

dns_op_t dns_op_value(const char *tag)
{
  return stoidef(tag,cm_dns_op_is,OP_COUNT,OP_UNKNOWN);
}

/**********************************************************************/
