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

/************************************************************************
*
* Definitions for a simple network interface to send and receive DNS
* queries.
* 
* This only suffices for simple applications; for anything that does a lot
* of DNS queries, you probably want to use something else.
*
* This file assumes C99.  You must include the following files before 
* including this one:
*
* #include <stdint.h>
* #include <stddef.h>
* #include <arpa/inet.h>
*
* And if you want to decode the return values (beyond success/failure):
*
* #include <errno.h>
*
*************************************************************************/

#ifndef NETSIMPLE_H
#define NETSIMPLE_H

#ifdef __cplusplus
  extern "C" {
#endif

#ifndef __GNUC__
#  define __attribute__(x)
#endif

typedef union sockaddr_all
{
  struct sockaddr     sa;
  struct sockaddr_in  sin;
  struct sockaddr_in6 sin6;
} sockaddr_all;

int 	net_server	(
			  sockaddr_all *const restrict,
			  const char   *const restrict
			) __attribute__ ((nonnull));
			
int 	net_request	(
			  sockaddr_all       *const restrict,
			  dns_packet_t       *const restrict,
			  size_t             *const restrict,
			  const dns_packet_t *const restrict,
			  const size_t
			) __attribute__ ((nonnull(1,2,3,4)));

#ifdef __cplusplus
  }
#endif
#endif
