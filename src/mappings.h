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

#ifndef DNS_MAPPINGS_H
#define DNS_MAPPINGS_H

#ifdef __cplusplus
  extern "C" {
#endif

#ifndef __GNUC__
#  define __attribute__(x)
#endif

const char 	*dns_rcode_text		(const enum dns_rcode)	__attribute__ ((pure,nothrow));
const char 	*dns_type_text 		(const enum dns_type)	__attribute__ ((pure,nothrow));
const char 	*dns_class_text		(const enum dns_class)	__attribute__ ((pure,nothrow));
const char 	*dns_op_text		(const enum dns_op)	__attribute__ ((pure,nothrow));

enum dns_type	 dns_type_value		(const char *const)	__attribute__ ((pure,nothrow,nonnull));
enum dns_class	 dns_class_value	(const char *const)	__attribute__ ((pure,nothrow,nonnull));
enum dns_op	 dns_op_value		(const char *const)	__attribute__ ((pure,nothrow,nonnull));

#ifdef __cplusplus
  }
#endif
#endif
