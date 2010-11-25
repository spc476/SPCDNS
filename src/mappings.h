
#ifndef DNS_MAPPINGS_H
#define DNS_MAPPINGS_H

const char 	*dns_rcode_text		(const enum dns_rcode);
const char 	*dns_type_text 		(const enum dns_type);
const char 	*dns_class_text		(const enum dns_class);
const char 	*dns_op_text		(const enum dns_op);

enum dns_type	 dns_type_value		(const char *);

#endif
