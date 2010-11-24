
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

char *dns_error(enum dns_rcode r,char *buf,size_t len)
{
  assert(buf != NULL);
  assert(len >  0);
  
  switch(r)
  {
    case RCODE_OKAY:            snprintf(buf,len,"Everything is under control"); break;
    case RCODE_FORMAT_ERROR:    snprintf(buf,len,"format error; could not parse answer"); break;
    case RCODE_SERVER_FAILURE:  snprintf(buf,len,"the server encounted a problem"); break;
    case RCODE_NAME_ERROR:      snprintf(buf,len,"domain name does not exist"); break;
    case RCODE_NOT_IMPLEMENTED: snprintf(buf,len,"not implemented"); break;
    case RCODE_REFUSED:         snprintf(buf,len,"server refused to answer"); break;
    
    case RCODE_DOMAIN_ERROR:    snprintf(buf,len,"problem parsing domain name"); break;
    case RCODE_DOMAIN_LOOP:     snprintf(buf,len,"domain name encoding leads to loop"); break;
    case RCODE_QUESTION_BAD:    snprintf(buf,len,"question could not be decoded"); break;
    case RCODE_MX_BAD_RECORD:   snprintf(buf,len,"invalid MX result"); break;
    case RCODE_ANSWER_BAD:      snprintf(buf,len,"response from server too short"); break;
    case RCODE_BAD_LENGTH:      snprintf(buf,len,"length of record exceeds data"); break;
    case RCODE_A_BAD_ADDR:      snprintf(buf,len,"A record bad"); break;
    case RCODE_UNKNOWN_OPTIONS: snprintf(buf,len,"reponse code unrecognized"); break;
    case RCODE_NO_MEMORY:       snprintf(buf,len,"insufficient memory to complete operation"); break;
    default:                    snprintf(buf,len,"%d - unknown error",r);
  }
  
  return buf;
}

char *type_name(enum dns_type t,char *buf,size_t len)
{
  assert(buf != NULL);
  assert(len >  6);
  
  switch(t)
  {
    case RR_A:		snprintf(buf,len,"A");		break;
    case RR_NS:		snprintf(buf,len,"NS");		break;
    case RR_MD: 	snprintf(buf,len,"MD");		break;
    case RR_MF: 	snprintf(buf,len,"MF");		break;
    case RR_CNAME:	snprintf(buf,len,"CNAME"); 	break;
    case RR_SOA:	snprintf(buf,len,"SOA");	break;
    case RR_MB:		snprintf(buf,len,"MB");		break;
    case RR_MG:		snprintf(buf,len,"MG");		break;
    case RR_MR:		snprintf(buf,len,"MR");		break;
    case RR_NULL:	snprintf(buf,len,"NULL");	break;
    case RR_WKS:	snprintf(buf,len,"WKS");	break;
    case RR_PTR:	snprintf(buf,len,"PTR");	break;
    case RR_HINFO:	snprintf(buf,len,"HINFO");	break;
    case RR_MINFO:	snprintf(buf,len,"MINFO");	break;
    case RR_MX:		snprintf(buf,len,"MX");		break;
    case RR_TXT:	snprintf(buf,len,"TXT");	break;
    case RR_ANY:	snprintf(buf,len,"ANY");	break;
    default:		snprintf(buf,len,"X-%d",t);	break;
  }
  return buf;
}

char *class_name(enum dns_class c,char *buf,size_t len)
{
  assert(buf != NULL);
  assert(len >  6);
  
  switch(c)
  {
    case CLASS_IN: snprintf(buf,len,"IN");     break;
    case CLASS_CS: snprintf(buf,len,"CS");     break;
    case CLASS_CH: snprintf(buf,len,"CH");     break;
    case CLASS_HS: snprintf(buf,len,"HS");     break;
    default:       snprintf(buf,len,"X-%d",c); break;
  }
  
  return buf;
}

void print_question(const char *tag,dns_question_t *pquest,size_t cnt)
{
  char type [16];
  char class[16];
  
  printf("\n;;; %s\n\n",tag);
  for (size_t i = 0 ; i < cnt ; i++)
  {
    printf(
    	";%s %s %s\n",
    	pquest[i].name,
    	class_name(pquest[i].class,class,sizeof(class)),
    	type_name (pquest[i].type, type, sizeof(type))
    );
  }
}

void print_answer(const char *tag,dns_answer_t *pans,size_t cnt)
{
  char ipaddr[32];
  char type [16];
  char class[16];
  
  printf("\n;;; %s\n\n",tag);
  
  for (size_t i = 0 ; i < cnt ; i++)
  {
    printf(
    	"%s %lu %s %s ",
    	pans[i].generic.name,
    	(unsigned long)pans[i].generic.ttl,
    	class_name(pans[i].generic.class,class,sizeof(class)),
    	type_name (pans[i].generic.type, type, sizeof(type))
    );
    
    switch(pans[i].generic.type)
    {
      case RR_NS: 
           printf("%s",pans[i].ns.nsdname);
           break;
      case RR_A:
           inet_ntop(AF_INET,&pans[i].a.address,ipaddr,32);
           printf("%s",ipaddr);
           break;
      case RR_MX:
           printf("%d %s",pans[i].mx.preference,pans[i].mx.exchange);
           break;
      case RR_PTR:
           printf("%s",pans[i].ptr.ptr);
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
  
  dns_question_t domains[argc];
  dns_query_t    query;
  uint8_t        buffer[MAX_DNS_QUERY_SIZE];
  size_t         len;
  int            rc;
  
  memset(domains,0,sizeof(domains));
  memset(&query,0,sizeof(query));
  
  for (int i = 1 ; i < argc ; i++)
  {
    domains[i - 1].name  = argv[i];
    domains[i - 1].type  = RR_PTR;
    domains[i - 1].class = CLASS_IN;
  }
  
  query.id        = 1234;
  query.query     = true;
  query.rd        = true;
  query.opcode    = OP_QUERY;
  query.qdcount   = argc - 1;
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

  char terror[BUFSIZ];
  
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
  	dns_error(result->rcode,terror,BUFSIZ)
  );
  	
  print_question("QUESTIONS"   ,result->questions   ,result->qdcount);
  print_answer  ("ANSWERS"     ,result->answers     ,result->ancount);
  print_answer  ("NAMESERVERS" ,result->nameservers ,result->nscount);
  print_answer  ("ADDITIONAL"  ,result->additional  ,result->arcount);

  return EXIT_SUCCESS;
}
