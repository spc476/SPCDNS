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
#include <errno.h>
#include <assert.h>

#include <arpa/inet.h>

#include <cgilib6/util.h>

#include "dns.h"
#include "mappings.h"
#include "netsimple.h"

#define DUMP 0

/************************************************************************/

static void print_question(const char *tag,dns_question_t *pquest,size_t cnt)
{
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

static void print_answer(const char *tag,dns_answer_t *pans,size_t cnt)
{
  char ipaddr[INET6_ADDRSTRLEN];
  
  printf("\n;;; %s\n\n",tag);
  
  for (size_t i = 0 ; i < cnt ; i++)
  {
    printf(
    	"%-16s\t%lu\t%s\t%s\t",
    	pans[i].generic.name,
    	(unsigned long)pans[i].generic.ttl,
    	dns_class_text(pans[i].generic.class),
    	dns_type_text (pans[i].generic.type)
    );
    
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
      case RR_SPF:
      case RR_TXT:
           if (pans[i].txt.len < 65)
             printf("\"%s\"",pans[i].txt.text);
           else
           {
             size_t len;
             int    max;
             size_t off;
             
             printf("(\n");
             len = pans[i].txt.len;
             off = 0;
             
             while(len)
             {
               max = (len > 64) ? 64 : (int)len;
               printf("\n\t\t\"%*.*s\"",max,max,&pans[i].txt.text[off]);
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
           
      default:
           break;
    }
    printf("\n");
  }
}

/*********************************************************************/

int main(int argc,char *argv[])
{
  if (argc == 1)
  {
    fprintf(stderr,"usage: %s type fqdn\n",argv[0]);
    return EXIT_FAILURE;
  }

  dns_question_t domains[2];
  size_t         dcnt;
  dns_query_t    query;
  dns_align_t    buffer[DNS_BUFFER_UDP];
  size_t         len;
  int            rc;
  
  memset(domains,0,sizeof(domains));
  memset(&query,0,sizeof(query));
  
  dcnt             = 1;
  domains[0].name  = argv[2];
  domains[0].type  = dns_type_value(argv[1]);
  domains[0].class = CLASS_IN;

#if 0

  /*------------------------------------------------------------------------
  ; I'm finding that many DNS servers only accept a single question in the
  ; query.  If there are any DNS servers that accept more than one question,
  ; I haven't located one yet.
  ;
  ; What I was attempting to do here was for A requests, include a request
  ; for the AAAA record, and if given an AAAA record, request the A record
  ; as well.
  ;------------------------------------------------------------------*/
  
  if (domains[0].type == RR_A)
  {
    dcnt++;
    domains[1].name  = argv[2];
    domains[1].type  = RR_AAAA;
    domains[1].class = CLASS_IN;
  }
  else if (domains[0].type == RR_AAAA)
  {
    dcnt++;
    domains[1].name  = argv[2];
    domains[1].type  = RR_A;
    domains[1].class = CLASS_IN;
  }
#endif

  query.id        = 1234;
  query.query     = true;
  query.rd        = true;
  query.opcode    = OP_QUERY;
  query.qdcount   = dcnt;
  query.questions = domains;
  
  len = sizeof(buffer);
  rc  = dns_encode(buffer,&len,&query);
  if (rc != RCODE_OKAY)
  {
    fprintf(stderr,"dns_encode() = (%d) %s\n",rc,dns_rcode_text(rc));
    return EXIT_FAILURE;
  }
  
#if DUMP
  printf("OUTGOING:\n\n");
  dump_memory(stdout,buffer,len,0);
#endif

  sockaddr_all server;
  dns_align_t  inbuffer[DNS_BUFFER_UDP];
  size_t       insize;

  rc = net_server(&server,"127.0.0.1");
  if (rc != 0)
  {
    fprintf(stderr,"net_server() = %s",strerror(rc)); 
    return EXIT_FAILURE;
  }
  
  insize = sizeof(inbuffer);
  if (net_request(&server,inbuffer,&insize,buffer,len) < 0)
  {
    fprintf(stderr,"failure\n");
    return EXIT_FAILURE;
  }

#if DUMP  
  printf("\nINCOMING:\n\n");
  dump_memory(stdout,inbuffer,insize,0);
#endif

  dns_align_t  bufresult[DNS_DECODEBUF_8K];
  dns_query_t *result;
  
  rc = dns_decode(bufresult,sizeof(bufresult),inbuffer,insize);
  if (rc != RCODE_OKAY)
  {
    fprintf(stderr,"dns_decode() = (%d) %s\n",rc,dns_rcode_text(rc));
    return EXIT_FAILURE;
  }
  
  result = (dns_query_t *)bufresult;

#if DUMP 
  syslog(LOG_DEBUG,"id:      %d",result->id);
  syslog(LOG_DEBUG,"qdcount: %lu",(unsigned long)result->qdcount);
  syslog(LOG_DEBUG,"ancount: %lu",(unsigned long)result->ancount);
  syslog(LOG_DEBUG,"nscount: %lu",(unsigned long)result->nscount);
  syslog(LOG_DEBUG,"arcount: %lu",(unsigned long)result->arcount);
#endif

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
