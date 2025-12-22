
/*
 * Copyright (C) 2025 Web Server LLC
 */


#ifndef _NGX_DTOA_H_INCLUDED_
#define _NGX_DTOA_H_INCLUDED_


#include <ngx_config.h>


/*
 * Sign (1) + first digit (1) + point (1) + rest digits (16) +
 * + exponent (1) + exponent sign (1) + exponent digits (3) == 23 bytes
 */

#define NGX_DTOA_MAX_LEN  32


size_t ngx_dtoa(u_char *p, double value);


#endif /* _NGX_DTOA_H_INCLUDED_ */
