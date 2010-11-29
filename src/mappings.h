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

/**************************************************************************
*
* Useful routines to convert error codes, RR, Class and Opcode values into
* strings, and strings into their equivilent RR, Class or Opcode values.
*
* This file assumes C99.  You must include the following files before
* including this one:
*
* #include "dns.h"
*
**************************************************************************/

#ifndef DNS_MAPPINGS_H
#define DNS_MAPPINGS_H

#ifdef __cplusplus
  extern "C" {
#endif

#ifndef __GNUC__
#  define __attribute__(x)
#endif

const char 	*dns_rcode_text		(const dns_rcode_t)	__attribute__ ((pure,nothrow));
const char 	*dns_type_text 		(const dns_type_t)	__attribute__ ((pure,nothrow));
const char 	*dns_class_text		(const dns_class_t)	__attribute__ ((pure,nothrow));
const char 	*dns_op_text		(const dns_op_t)	__attribute__ ((pure,nothrow));

dns_type_t	 dns_type_value		(const char *const)	__attribute__ ((pure,nothrow,nonnull));
dns_class_t	 dns_class_value	(const char *const)	__attribute__ ((pure,nothrow,nonnull));
dns_op_t	 dns_op_value		(const char *const)	__attribute__ ((pure,nothrow,nonnull));

#ifdef __cplusplus
  }
#endif
#endif
