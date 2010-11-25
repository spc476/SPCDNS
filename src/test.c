
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <poll.h>
#include <unistd.h>
#include <fcntl.h>
#include <syslog.h>

#include <cgilib6/util.h>

#include "dns.h"
#include "mappings.h"

#define DUMP 1

/************************************************************************/

typedef union sockaddr_all
{
  struct sockaddr    ss;
  struct sockaddr_in sin;
} sockaddr_all;

/***********************************************************************/

int send_request(
	uint8_t                       *dest,
	size_t                        *dsize,
	const uint8_t *const restrict  src,
	const size_t                   ssize
)
{
  sockaddr_all srvaddr;
  ssize_t      bytes;
  int          sock;
  int          err;
  
  assert(dest   != NULL);
  assert(dsize  != NULL);
  assert(*dsize >= 512);
  assert(src    != NULL);
  assert(ssize  >= 12);
  
  sock = socket(AF_INET,SOCK_DGRAM,0);
  if (sock < 0)
  {
    err = errno;
    fprintf(stderr,"socket(DGRAM) = %s",strerror(errno));
    return err;
  }

  memset(&srvaddr,0,sizeof(srvaddr));
  srvaddr.sin.sin_family = AF_INET;
  srvaddr.sin.sin_port   = htons(53);
  inet_pton(AF_INET,"127.0.0.1",&srvaddr.sin.sin_addr.s_addr);
  
  bytes = sendto(sock,src,ssize,0,&srvaddr.ss,sizeof(struct sockaddr_in));
  if (bytes < 0)
  {
    err = errno;
    fprintf(stderr,"sendto(127.0.0.1:53) = %s",strerror(errno));
    close(sock);
    return err;
  }
  
  if ((size_t)bytes < ssize)
  {
    err = errno;
    fprintf(stderr,"sendto(127.0.0.1:53) truncated");
    close(sock);
    return err;
  }
  
  bytes = recvfrom(sock,dest,*dsize,0,NULL,NULL);
  
  if (bytes < 0)
  {
    err = errno;
    fprintf(stderr,"recvfrom(127.0.0.1:53) = %s",strerror(errno));
    close(sock);
    return err;
  }
  
  *dsize = bytes;
  return 0;
}

/**********************************************************************/

void print_question(const char *tag,dns_question_t *pquest,size_t cnt)
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

void print_answer(const char *tag,dns_answer_t *pans,size_t cnt)
{
  char ipaddr[INET6_ADDRSTRLEN];
  
  printf("\n;;; %s\n\n",tag);
  
  for (size_t i = 0 ; i < cnt ; i++)
  {
    printf(
    	"%s %lu %s %s ",
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
           inet_ntop(AF_INET6,&pans[i].aaaa.ipv6,ipaddr,sizeof(ipaddr));
           printf("%s",ipaddr);
           break;
      case RR_MX:
           printf("%d %s",pans[i].mx.preference,pans[i].mx.exchange);
           break;
      case RR_PTR:
           printf("%s",pans[i].ptr.ptr);
           break;
      case RR_HINFO:
           printf("\"%s\" \"%s\"",pans[i].hinfo.cpu,pans[i].hinfo.os);
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
           	"%d %d (\n"
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
      case RR_SRV:
           printf(
           	"%d %d %d %s",
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

int main(int argc,char *argv[])
{
  if (argc == 1)
  {
    fprintf(stderr,"usage: %s fqdn\n",argv[0]);
    return EXIT_FAILURE;
  }
  
  dns_question_t domains[2];
  size_t         dcnt;
  dns_query_t    query;
  uint8_t        buffer[MAX_DNS_QUERY_SIZE];
  size_t         len;
  int            rc;
  
  memset(domains,0,sizeof(domains));
  memset(&query,0,sizeof(query));
  
  dcnt             = 1;
  domains[0].name  = argv[2];
  domains[0].type  = dns_type_value(argv[1]);
  domains[0].class = CLASS_IN;

#if 0
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
    fprintf(stderr,"dns_encode() = %d\n",rc);
    return EXIT_FAILURE;
  }
  
#if DUMP
  printf("OUTGOING:\n\n");
  dump_memory(stdout,buffer,len,0);
#endif

  uint8_t inbuffer[MAX_DNS_QUERY_SIZE];
  size_t  insize;

  insize = sizeof(inbuffer);
  if (send_request(inbuffer,&insize,buffer,len) < 0)
  {
    fprintf(stderr,"failure\n");
    return EXIT_FAILURE;
  }

#if DUMP  
  printf("\nINCOMING:\n\n");
  dump_memory(stdout,inbuffer,insize,0);
#endif

  uint8_t      bufresult[8192];
  dns_query_t *result;
  
  rc = dns_decode(bufresult,sizeof(bufresult),inbuffer,insize);
  if (rc != RCODE_OKAY)
  {
    fprintf(stderr,"dns_decode() = %d\n",rc);
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
