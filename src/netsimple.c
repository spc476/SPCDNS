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

/*********************************************************************
*
* Implementation of the simple network interface for DNS queries.  Two
* functions are exported:
*
*	net_server()
*
*		decode the IP address (IPv4/IPv6) from a text representation
*		to a network format.
*
*	net_request()
*
*		Send a request to the given server and wait a reponse.  This
*		function is stupid simple---it opens a socket, sends the
*		request via sendto(), waits for up to 15 seconds for a
*		reply.  If no reply is seen in 15 seconds, close the socket
*		and return an error---otherwise, call recvfrom(), close the
*		socket and return the data.
*
*		Like I said, stupid simple.  It's enough for testing and
*		very simple programs.
*
* This code is written for C99.
*
**************************************************************************/

#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>

#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <poll.h>
#include <unistd.h>

#include "dns.h"
#include "netsimple.h"

/************************************************************************/

int net_server(
	sockaddr_all *const restrict addr,
	const char   *const restrict host
)
{
  assert(addr != NULL);
  assert(host != NULL);
  
  memset(addr,0,sizeof(sockaddr_all));
  
  if (inet_pton(AF_INET,host,&addr->sin.sin_addr.s_addr) < 0)
  {
    if (inet_pton(AF_INET6,host,&addr->sin6.sin6_addr.s6_addr) < 0)
      return errno;
    addr->sin6.sin6_family = AF_INET6;
    addr->sin6.sin6_port   = htons(53);
  }
  else
  {
    addr->sin.sin_family = AF_INET;
    addr->sin.sin_port   = htons(53);
  }
  
  return 0;
}

/************************************************************************/

int net_request(
	sockaddr_all       *const restrict srvaddr,
	dns_packet_t       *const restrict dest,
	size_t             *const restrict dsize,
	const dns_packet_t *const restrict src,
	const size_t                      ssize
)
{
  struct pollfd polldat;
  socklen_t     asize;
  ssize_t       bytes;
  int           sock;
  int           rc;
  int           err;
  
  switch(srvaddr->sa.sa_family)
  {
    case AF_INET:  asize = sizeof(struct sockaddr_in);  break;
    case AF_INET6: asize = sizeof(struct sockaddr_in6); break;
    default:       assert(0); return EPROTOTYPE;
  }

  sock = socket(srvaddr->sa.sa_family,SOCK_DGRAM,0);
  if (sock < 0)
    return errno;

  bytes = sendto(sock,src,ssize,0,&srvaddr->sa,asize);
  if (bytes < 0)
  {
    err = errno;
    close(sock);
    return err;
  }

  polldat.fd     = sock;
  polldat.events = POLLIN;
  
  rc = poll(&polldat,1,15000);
  if (rc < 0)
  {
    err = errno;
    close(sock);
    return err;
  }
  
  if (rc == 0)
  {
    close(sock);
    return ETIMEDOUT;
  }

  bytes = recvfrom(sock,dest,*dsize,0,NULL,NULL);
  if (bytes < 0)
  {
    int err = errno;
    close(sock);
    return err;
  }

  *dsize = bytes;
  close(sock);
  return 0;
}

/**************************************************************************/
