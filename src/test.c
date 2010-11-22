
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
  printf("%s\n",tag);
  for (size_t i = 0 ; i < cnt ; i++)
  {
    printf(
    	"\t%s %s %s\n",
    	pquest[i].name,
    	c_dns_class_names[pquest[i].class],
    	c_dns_type_names[pquest[i].type]
    );
  }
}

void print_answer(const char *tag,dns_answer_t *pans,size_t cnt)
{
  printf("%s\n",tag);
  
  for (size_t i = 0 ; i < cnt ; i++)
  {
    syslog(
  	LOG_DEBUG,
  	"name: %s type: %02x class: %02x ttl: %08lx",
  	pans[i].generic.name,
  	pans[i].generic.type,
  	pans[i].generic.class,
  	(unsigned long)(pans[i].generic.ttl)
    );
    printf(
    	"\t%s %lu %s %s\n",
    	pans[i].generic.name,
    	(unsigned long)pans[i].generic.ttl,
    	c_dns_class_names[pans[i].generic.class],
    	c_dns_type_names[pans[i].generic.type]
    );
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
    domains[i - 1].name = argv[i];
    domains[i - 1].type = RR_MX;
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
  
  printf("OUTGOING:\n\n");
  dump_memory(stdout,buffer,len,0);
  
  uint8_t inbuffer[MAX_DNS_QUERY_SIZE];
  size_t  insize;

  insize = sizeof(inbuffer);
  if (send_request(inbuffer,&insize,buffer,len) < 0)
  {
    fprintf(stderr,"failure\n");
    return EXIT_FAILURE;
  }
  
  printf("\nINCOMING:\n\n");
  dump_memory(stdout,inbuffer,insize,0);
  
  dns_query_t result;
  
  dns_decode(&result,inbuffer,insize);
  
  syslog(LOG_DEBUG,"id:      %d",result.id);
  syslog(LOG_DEBUG,"qdcount: %lu",(unsigned long)result.qdcount);
  syslog(LOG_DEBUG,"ancount: %lu",(unsigned long)result.ancount);
  syslog(LOG_DEBUG,"nscount: %lu",(unsigned long)result.nscount);
  syslog(LOG_DEBUG,"arcount: %lu",(unsigned long)result.arcount);
  
  print_question("QUESTIONS"   ,result.questions   ,result.qdcount);
  print_answer  ("ANSWERS"     ,result.answers     ,result.ancount);
  print_answer  ("NAMESERVERS" ,result.nameservers ,result.nscount);
  print_answer  ("ADDITIONAL"  ,result.additional  ,result.arcount);

  return EXIT_SUCCESS;
}
