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
* Sample application using my DNS library.  It's somewhat similar to dig,
* but lacking features found in dig.  Still useful though, and gives an
* example of how to use the DNS library.
*
* This code is C99.
*
***************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>

#include <getopt.h>
#include <arpa/inet.h>

#include "dns.h"
#include "mappings.h"
#include "netsimple.h"

enum
{
  OPT_NONE	= '\0',
  OPT_HELP	= 'h',
  OPT_EDNS      = 'e',
  OPT_SERVER	= 's',
  OPT_DUMP	= 'd',
  OPT_ERR	= '?'
};

/************************************************************************/

static void print_question	(const char *,dns_question_t *,size_t);
static void print_answer	(const char *,dns_answer_t   *,size_t);
static void usage		(const char *);
static void dump_memory		(FILE *,const void *,size_t,size_t);

/************************************************************************/

const struct option c_options[] =
{
  { "server"	, required_argument	, NULL	, OPT_SERVER 	} ,
  { "edns"	, no_argument		, NULL  , OPT_EDNS	} ,
  { "dump"	, no_argument		, NULL	, OPT_DUMP	} ,
  { "help"	, no_argument		, NULL	, OPT_HELP	} ,
  { NULL	, 0			, NULL	, 0		}
};

/***********************************************************************/

int main(int argc,char *argv[])
{
  const char *serverhost;
  const char *host;
  const char *type;
  bool        fdump;
  bool        fedns;
  int         option;
  int         rc;
  
  /*-------------------------------------------------------------------------
  ; verbiage to parse the command line and set some sane defaults, yada yada
  ; blah blah blah
  ;------------------------------------------------------------------*/
  
  serverhost = "127.0.0.1";
  host       = "examle.net";
  type       = "A";
  fdump      = false;
  fedns      = false;
  option     = 0;
  opterr     = 0; /* prevent getopt_long() from printing error messages */
  
  while(true)
  {
    rc = getopt_long(argc,argv,"hdes:",c_options,&option);
    if (rc == EOF) break;
    
    switch(rc)
    {
      default:
      case OPT_ERR:
           fprintf(stderr,"unknown option '%c'\n",optopt);
      case OPT_HELP:
           usage(argv[0]);
           return EXIT_FAILURE;
      case OPT_SERVER:
           serverhost = optarg;
           break;
      case OPT_EDNS:
           fedns = true;
           break;
      case OPT_DUMP:
           fdump = true;
           break;
      case OPT_NONE:
           break;
    }
  }
  
  if (optind == argc)
  {
    usage(argv[0]);
    return EXIT_FAILURE;
  }
  
  host = argv[optind++];
  
  if (optind < argc)
    type = argv[optind];
  
  /*------------------------------------------------------------------------
  ; Encoding of a DNS query.  I'm finding that many (if not all) DNS servers
  ; only accept a single question, even though the protocol seems to allow
  ; more than one question.  If there *is* a DNS server that can handle
  ; multiple questions, then we can handle them, even if they don't exist
  ; yet.
  ;--------------------------------------------------------------------*/
  
  dns_question_t domain;
  dns_query_t    query;
  dns_packet_t   request[DNS_BUFFER_UDP];
  size_t         reqsize;
  edns0_opt_t    opt;
  dns_answer_t   edns;
  
  domain.name  = host;
  domain.type  = dns_type_value(type);
  domain.class = CLASS_IN;

  query.id          = 1234;	/* should be a random value */
  query.query       = true;
  query.opcode      = OP_QUERY;
  query.aa          = false;
  query.tc          = false;
  query.rd          = true;
  query.ra          = false;
  query.ad          = false;
  query.cd          = false;
  query.rcode       = RCODE_OKAY;
  query.qdcount     = 1;
  query.questions   = &domain;
  query.ancount     = 0;
  query.answers     = NULL;
  query.nscount     = 0;
  query.nameservers = NULL;
  query.arcount     = 0;
  query.additional  = NULL;
  
  if (fedns)
  {
    /*----------------------------------------------------------------------
    ; Test EDNS0 by sending an NSID OPT RR type query.  
    ;
    ; The udp_payload is the largest UDP packet we can reasonably expect to
    ; receive.  I'm using the value 1464 since that's about the largest UDP
    ; packet that can fit into an Ethernet frame (20 bytes IP header, 8
    ; bytes UDP header; RFC-1042 based Ethernet frame).
    ;
    ; Additionally, OPT RRs *MUST* be in the additional section of a DNS
    ; packet, and there can be only one (Highlander 2 & 3?  Never happened;
    ; neither did the TV series) OPT RR.
    ;----------------------------------------------------------------------*/
    
    opt.code = EDNS0RR_NSID;
    opt.data = (uint8_t *)"MY-DNS-SERVER-ID";
    opt.len  = strlen((char *)opt.data);
    
    edns.opt.name        = ".";
    edns.opt.type        = RR_OPT;
    edns.opt.class       = CLASS_UNKNOWN;
    edns.opt.ttl         = 0;
    edns.opt.udp_payload = 1464;
    edns.opt.version     = 0;
    edns.opt.fdo         = false;
    edns.opt.numopts     = 1;
    edns.opt.opts        = &opt;
    
    query.arcount    = 1;
    query.additional = &edns;
  }
 
  reqsize = sizeof(request);
  rc      = dns_encode(request,&reqsize,&query);
  if (rc != RCODE_OKAY)
  {
    fprintf(stderr,"dns_encode() = (%d) %s\n",rc,dns_rcode_text(rc));
    return EXIT_FAILURE;
  }
  
  if (fdump)
  {  
    printf("OUTGOING:\n\n");
    dump_memory(stdout,request,reqsize,0);
  }

  /*-----------------------------------------------------------------------
  ; Sending a DNS query.  This uses the simple interface provided and is
  ; not good for much *except* as an example.  If you have any complex
  ; requirements, do not look to this code.
  ;-----------------------------------------------------------------------*/
  
  sockaddr_all server;
  dns_packet_t reply[DNS_BUFFER_UDP];
  size_t       replysize;

  rc = net_server(&server,serverhost);
  if (rc != 0)
  {
    fprintf(stderr,"net_server() = %s",strerror(rc)); 
    return EXIT_FAILURE;
  }
  
  replysize = sizeof(reply);
  if (net_request(&server,reply,&replysize,request,reqsize) < 0)
  {
    fprintf(stderr,"failure\n");
    return EXIT_FAILURE;
  }

  if (fdump)
  {
    printf("\nINCOMING:\n\n");
    dump_memory(stdout,reply,replysize,0);
  }

  /*----------------------------------------------------------------------
  ; Decode a DNS packet into something we can use.  dns_decoded_t is a type
  ; to ensure proper alignment for stack based results---this must be big
  ; enough to handle not only the dns_query_t but additional information as
  ; well.  The 4K size so far seems good enough for decoding UDP packets,
  ; although I'm using the 8K size just in case.
  ;-----------------------------------------------------------------------*/
  
  dns_decoded_t  bufresult[DNS_DECODEBUF_8K];
  size_t         bufsize;
  dns_query_t   *result;
  
  bufsize = sizeof(bufresult);
  rc = dns_decode(bufresult,&bufsize,reply,replysize);
  if (rc != RCODE_OKAY)
  {
    fprintf(stderr,"dns_decode() = (%d) %s\n",rc,dns_rcode_text(rc));
    return EXIT_FAILURE;
  }
  
  if (fdump)
    printf("\nBytes used: %lu\n\n",(unsigned long)bufsize);
  
  result = (dns_query_t *)bufresult;

  /*-------------------------------------------
  ; Print the results out, ala dig
  ;-------------------------------------------*/

  printf(
  	"; Questions            = %lu\n"
  	"; Answers              = %lu\n"
  	"; Name Servers         = %lu\n"
  	"; Additional Records   = %lu\n"
  	"; Authoritative Result = %s\n"
  	"; Truncated Result     = %s\n"
  	"; Recursion Desired    = %s\n"
  	"; Recursion Available  = %s\n"
  	"; Result               = %s\n",
  	(unsigned long)result->qdcount,
  	(unsigned long)result->ancount,
  	(unsigned long)result->nscount,
  	(unsigned long)result->arcount,
  	result->aa ? "true" : "false",
  	result->tc ? "true" : "false",
  	result->rd ? "true" : "false",
  	result->ra ? "true" : "false",
  	dns_rcode_text(result->rcode)
  );
  	
  print_question("QUESTIONS"   ,result->questions   ,result->qdcount);
  print_answer  ("ANSWERS"     ,result->answers     ,result->ancount);
  print_answer  ("NAMESERVERS" ,result->nameservers ,result->nscount);
  print_answer  ("ADDITIONAL"  ,result->additional  ,result->arcount);

  return EXIT_SUCCESS;
}

/************************************************************************/

static void print_question(const char *tag,dns_question_t *pquest,size_t cnt)
{
  assert(tag    != NULL);
  assert(pquest != NULL);
  
  printf("\n;;; %s\n\n",tag);
  for (size_t i = 0 ; i < cnt ; i++)
  {
    printf(
    	";%s %s %s\n",
    	pquest[i].name,
    	dns_class_text(pquest[i].class),
    	dns_type_text (pquest[i].type)
    );
  }
}

/***********************************************************************/

static void print_answer(const char *tag,dns_answer_t *pans,size_t cnt)
{
  char ipaddr[INET6_ADDRSTRLEN];
  
  assert(tag  != NULL);
  assert(pans != NULL);
  
  printf("\n;;; %s\n\n",tag);
  
  for (size_t i = 0 ; i < cnt ; i++)
  {
    if (pans[i].generic.type != RR_OPT)
    {
      printf(
    	"%-16s\t%5lu\t%s\t%s\t",
    	pans[i].generic.name,
    	(unsigned long)pans[i].generic.ttl,
    	dns_class_text(pans[i].generic.class),
    	dns_type_text (pans[i].generic.type)
      );
    }
    else
      printf("; OPT RR");
    
    switch(pans[i].generic.type)
    {
      case RR_NS: 
           printf("%s",pans[i].ns.nsdname);
           break;
      case RR_A:
           inet_ntop(AF_INET,&pans[i].a.address,ipaddr,sizeof(ipaddr));
           printf("%s",ipaddr);
           break;
      case RR_AAAA:
           inet_ntop(AF_INET6,&pans[i].aaaa.address,ipaddr,sizeof(ipaddr));
           printf("%s",ipaddr);
           break;
      case RR_CNAME:
           printf("%s",pans[i].cname.cname);
           break;
      case RR_MX:
           printf("%5d %s",pans[i].mx.preference,pans[i].mx.exchange);
           break;
      case RR_PTR:
           printf("%s",pans[i].ptr.ptr);
           break;
      case RR_HINFO:
           printf("\"%s\" \"%s\"",pans[i].hinfo.cpu,pans[i].hinfo.os);
           break;
      case RR_MINFO:
           printf("(\n\t\t\"%s\"\n\t\t\"%s\" )",pans[i].minfo.rmailbx,pans[i].minfo.emailbx);
           break;
      case RR_SPF:
      case RR_TXT:
           if (pans[i].txt.len < 30)
             printf("\"%s\"",pans[i].txt.text);
           else
           {
             size_t len;
             int    max;
             size_t off;
             
             printf("(");
             len = pans[i].txt.len;
             off = 0;
             
             while(len)
             {
               max = (len > 64) ? 64 : (int)len;
               printf("\n\t\"%*.*s\"",max,max,&pans[i].txt.text[off]);
               off += max;
               len -= max;
             }
             
             printf("\n\t\t)\n");
           }
           break;
      case RR_SOA:
           printf(
           	"%s %s (\n"
           	"\t\t%10lu   ; Serial\n"
           	"\t\t%10lu   ; Refresh\n"
           	"\t\t%10lu   ; Retry\n"
           	"\t\t%10lu   ; Expire\n"
           	"\t\t%10lu ) ; Miminum\n",
           	pans[i].soa.mname,
           	pans[i].soa.rname,
           	(unsigned long)pans[i].soa.serial,
           	(unsigned long)pans[i].soa.refresh,
           	(unsigned long)pans[i].soa.retry,
           	(unsigned long)pans[i].soa.expire,
           	(unsigned long)pans[i].soa.minimum
           );
           break;
      case RR_NAPTR:
           printf(
           	"%5d %5d (\n"
           	"\t\t\"%s\"\n"
           	"\t\t\"%s\"\n"
           	"\t\t\"%s\"\n"
           	"\t\t%s )\n",
           	pans[i].naptr.order,
           	pans[i].naptr.preference,
           	pans[i].naptr.flags,
           	pans[i].naptr.services,
           	pans[i].naptr.regexp,
           	pans[i].naptr.replacement
           );
           break;
      case RR_LOC:
           printf(
           	"(\n"
           	"\t\t%3d %2d %2d %s ; Latitude\n"
           	"\t\t%3d %2d %2d %s ; Longitude\n"
           	"\t\t%11ld ; Altitude\n"
           	"\t\t%11lu ; Size\n"
           	"\t\t%11lu ; Horizontal Precision\n"
           	"\t\t%11lu ; Vertical Precision\n"
           	"\t\t)\n",
           	pans[i].loc.latitude.deg,
           	pans[i].loc.latitude.min,
           	pans[i].loc.latitude.sec,
           	pans[i].loc.latitude.nw ? "N" : "S",
           	pans[i].loc.longitude.deg,
           	pans[i].loc.longitude.min,
           	pans[i].loc.longitude.sec,
           	pans[i].loc.longitude.nw ? "W" : "E",
           	pans[i].loc.altitude,
           	pans[i].loc.size,
           	pans[i].loc.horiz_pre,
           	pans[i].loc.vert_pre
           );
           break;
      case RR_SRV:
           printf(
           	"%5d %5d %5d %s",
           	pans[i].srv.priority,
           	pans[i].srv.weight,
           	pans[i].srv.port,
           	pans[i].srv.target
           );
           break;
      case RR_OPT:
           printf(
           	"\n"
           	";\tpayload = %lu\n"
           	";\tDO      = %s\n"
           	";\t#opts   = %lu\n",
           	(unsigned long)pans[i].opt.udp_payload,
           	pans[i].opt.fdo ? "true" : "false",
           	(unsigned long)pans[i].opt.numopts
           );
           break;
           
      default:
           break;
    }
    printf("\n");
  }
}

/*********************************************************************/

static void usage(const char *prog)
{
  assert(prog != NULL);
  
  fprintf(
  	stderr,
  	"usage: %s [-h] [-d] [-e] [-s server] host [type]\n"
  	"\t-h\t\tusage text (this text)\n"
  	"\t-d\t\tdump raw DNS queries\n"
  	"\t-e\t\tInclude EDNS0 RR with query\n"
  	"\t-s server\tIP address of server\n"
  	"\n"
  	"\ttype\t\tRR DNS type\n",
  	prog
  );
}

/**********************************************************************/

#define LINESIZE	16

static void dump_memory(FILE *out,const void *data,size_t size,size_t offset)
{
  const unsigned char *block = data;
  char                 ascii[LINESIZE + 1];
  int                  skip;
  int                  j;
  
  assert(out   != NULL);
  assert(block != NULL);
  assert(size  >  0);
  
  while(size > 0)
  {
    fprintf(out,"%08lX: ",(unsigned long)offset);
    
    for (skip = offset % LINESIZE , j = 0 ; skip ; j++ , skip--)
    {
      fputs("   ",out);
      ascii[j] = ' ';
    }
    
    do
    {
      fprintf(out,"%02x ",*block);
      if (isprint(*block))
        ascii[j] = *block;
      else
        ascii[j] = '.';
      
      block++;
      offset++;
      j++;
      size--;
    } while((j < LINESIZE) && (size > 0));
    
    ascii[j] = '\0';

    if (j < LINESIZE)
    {
      int i;
      
      for (i = j ; i < LINESIZE ; i++)
        fputs("   ",out);
    }
    fprintf(out,"%s\n",ascii);
  }
}

/**********************************************************************/

