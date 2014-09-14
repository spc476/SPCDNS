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
* DNS record output functions used by sample application.
*
* It was factored out so it could be called from client applications.
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
#include "output.h"

/************************************************************************/

void dns_print_result(dns_query_t* presult)
{
  /*-------------------------------------------
  ; Print the results out, ala dig
  ;-------------------------------------------*/

  dns_print_header(presult);
  dns_print_question("QUESTIONS"   ,presult->questions   ,presult->qdcount);
  dns_print_answer  ("ANSWERS"     ,presult->answers     ,presult->ancount);
  dns_print_answer  ("NAMESERVERS" ,presult->nameservers ,presult->nscount);
  dns_print_answer  ("ADDITIONAL"  ,presult->additional  ,presult->arcount);
}

/************************************************************************/

void dns_print_header(dns_query_t* presult)
{
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
  	(unsigned long)presult->qdcount,
  	(unsigned long)presult->ancount,
  	(unsigned long)presult->nscount,
  	(unsigned long)presult->arcount,
  	presult->aa ? "true" : "false",
  	presult->tc ? "true" : "false",
  	presult->rd ? "true" : "false",
  	presult->ra ? "true" : "false",
  	dns_rcode_text(presult->rcode)
  );
}

/************************************************************************/

void dns_print_question(const char *tag,dns_question_t *pquest,size_t cnt)
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

void dns_print_answer(const char *tag,dns_answer_t *pans,size_t cnt)
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

/**********************************************************************/

#define LINESIZE	16

void dns_dump_memory(FILE *out,const void *data,size_t size,size_t offset)
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
