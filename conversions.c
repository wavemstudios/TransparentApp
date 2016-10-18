/*
 * conversions.c
 *
 *  Created on: 11 Oct 2016
 *      Author: steve
 */

#include <stdio.h>
#include <stdint.h>


char *bin2hex(char *out, const void *in, size_t len)
{
	const char *p = (const char *)in;
	size_t i;

	for (i = 0; i < len; i++) {
		char digit;

		digit = p[i] >> 4;
		digit = digit < 0xA ? digit + '0' : digit - 10 + 'A';
		out[2 * i] = digit;

		digit = p[i] & 0xF;
		digit = digit < 0xA ? digit + '0' : digit - 10 + 'A';
		out[2 * i + 1] = digit;
	}

	out[2 * len] = '\0';

	return out;
}

int hex2bin( const char *s )
{
    int ret=0;
    int i;
    for( i=0; i<2; i++ )
    {
        char c = *s++;
        int n=0;
        if( '0'<=c && c<='9' )
            n = c-'0';
        else if( 'a'<=c && c<='f' )
            n = 10 + c-'a';
        else if( 'A'<=c && c<='F' )
            n = 10 + c-'A';
        ret = n + ret*16;
    }
    return ret;
}

