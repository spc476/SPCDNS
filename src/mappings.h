
#ifndef DNS_MAPPINGS_H
#define DNS_MAPPINGS_H

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

#endif
