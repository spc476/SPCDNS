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
#include "output.h"

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

static void usage		(const char *);

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
  host       = "example.net";
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
  query.z           = false;
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
    dns_dump_memory(stdout,request,reqsize,0);
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
  rc = net_request(&server,reply,&replysize,request,reqsize);
  if (rc != 0)
  {
    fprintf(stderr,"net_request() = %s\n",strerror(rc));
    return EXIT_FAILURE;
  }

  if (fdump)
  {
    printf("\nINCOMING:\n\n");
    dns_dump_memory(stdout,reply,replysize,0);
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
  
  bufsize = sizeof(bufresult);
  rc = dns_decode(bufresult,&bufsize,reply,replysize);
  if (rc != RCODE_OKAY)
  {
    fprintf(stderr,"dns_decode() = (%d) %s\n",rc,dns_rcode_text(rc));
    return EXIT_FAILURE;
  }
  
  if (fdump)
    printf("\nBytes used: %lu\n\n",(unsigned long)bufsize);
  
  /*----------------------------------------
  ; see the code in output.c 
  ;-----------------------------------------*/
  
  dns_print_result((dns_query_t *)bufresult);
  return EXIT_SUCCESS;
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
