/* ----------------------------------------------------------------------- *
 *   
 *   Copyright 1994-2008 H. Peter Anvin - All Rights Reserved
 *
 *   This E_main_S_program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, Inc., 51 Franklin St, Fifth Floor,
 *   Boston MA 02110-1301, USA; either version 3 of the License, or
 *   (at your option) any later version; incorporated herein by reference.
 *
 * ----------------------------------------------------------------------- */

/*
 * ranpwd.c: Generate random passwords using the Linux kernel-based true
 *           random number generator (if available.)
 */

#include "config.h"

#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <ctype.h>
#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif

#include "main.h"
#include "random.h"

extern _Bool E_random_S_secure_source;

const char *E_main_S_program;

enum extended_options {
  OPT_UPPER = 256,
  OPT_LOWER,
  OPT_ASCII,
};

static const char *short_options = "aluxXdobALUimgGMschV";
#ifdef HAVE_GETOPT_LONG
const struct option long_options[] = {
  { "ascii",        0, 0, OPT_ASCII },
  { "alphanum",		0, 0, 'a' },
  { "lc-alphanum",	0, 0, 'l' },
  { "uc-alphanum",	0, 0, 'u' },
  { "hexadecimal",	0, 0, 'x' },
  { "decimal",		0, 0, 'd' },
  { "octal",		0, 0, 'o' },
  { "binary",		0, 0, 'b' },
  { "alpha",		0, 0, 'A' },
  { "lc-alpha",		0, 0, 'L' },
  { "uc-alpha",		0, 0, 'U' },
  { "upper",		0, 0, OPT_UPPER },
  { "lower",		0, 0, OPT_LOWER },
  { "ip",           0, 0, 'i' },
  { "mac-address",  0, 0, 'm' },
  { "guid",         0, 0, 'g' },
  { "uuid",         0, 0, 'g' },
  { "uc-guid",      0, 0, 'G' },
  { "uc-uuid",      0, 0, 'G' },
  { "secure",       0, 0, 's' },
  { "c",		    0, 0, 'c' },
  { "help",         0, 0, 'h' },
  { "version",      0, 0, 'V' },
  { 0, 0, 0, 0 }
};
#define LO(X) X
#else
#define getopt_long(C,V,O,L,I) getopt(C,V,O)
#define LO(X)
#endif

static void usage(int err)
{
  fprintf(stderr,
	  "%s %s\n"
	  "Usage: %s [options] [length]\n"
	  LO("  --ascii              " "      Any ASCII characters\n")
	  LO("  --alphanum           ")"  -a  Alphanumeric\n"
	  LO("  --alphanum --lower   ")"  -l  Lower case alphanumeric\n"
	  LO("  --alphanum --upper   ")"  -u  Upper case alphanumeric\n"
	  LO("  --alpha              ")"  -A  Alphabetic\n"
	  LO("  --alpha --lower      ")"  -L  Lower case alphabetic\n"
	  LO("  --alpha --upper      ")"  -U  Upper case alphabetic\n"
	  LO("  --decimal            ")"  -d  Decimal number\n"
	  LO("  --hexadecimal        ")"  -x  Lower case hexadecimal\n"
	  LO("  --hexadecimal --upper")"  -X  Upper case hexadecimal\n"
	  LO("  --octal              ")"  -o  Octal number\n"
	  LO("  --binary             ")"  -b  Binary number\n"
	  LO("  --c                  ")"  -c  C language constant\n"
	  LO("  --ip                 ")"  -i  IP address\n"
	  LO("  --mac-address        ")"  -m  Ethernet MAC address\n"
	  LO("  --mac-address --upper")"  -M  Upper case Ethernet MAC address\n"
	  LO("  --uuid               ")"  -g  UUID/GUID\n"
	  LO("  --uuid --upper       ")"  -G  Upper case UUID/GUID\n"
	  LO("  --secure             ")"  -s  Slower but more secure\n"
	  LO("  --help               ")"  -h  Show this message\n"
	  LO("  --version            ")"  -V  Display E_main_S_program version\n"
	  , PACKAGE_NAME, PACKAGE_VERSION, E_main_S_program);
  exit(err);
}

/*
 * cputc():
 *
 * putchar(), with option to escape characters that have to be escaped in C
 */
static void cputc(int ch, int esc) {
  if(esc) {
    switch ( ch ) {
    case '\"': case '\\':
    case '\'':
      putchar('\\');
    default:
      break;
    }
  }
  putchar(ch);
}

enum output_type {
  ty_ascii, ty_lascii, ty_uascii,
  ty_anum, ty_lcase, ty_ucase,
  ty_alpha, ty_alcase, ty_aucase,
  ty_hex, ty_uhex,
  ty_ip,
  ty_mac, ty_umac,
  ty_uuid, ty_uuuid,
  ty_dec, ty_oct, ty_binary
};

static
int
bits_in_range( unsigned min
, unsigned max
){  return sizeof(unsigned) * 8 - __builtin_clz( max - min + 1 - 1 );
}

static
int
output_random_single_range( enum output_type type
, int n
, int decor
, unsigned char min
, unsigned char max
){  unsigned bits = bits_in_range( min, max );
    if( E_random_I_prepare_data( n * bits ))
        return ~0;
    while( n-- )
    {   unsigned char c = E_random_R_bits(bits);
        c += min;
        if( c > max )
            c = c - ( max + 1 ) + min;
        cputc( c, decor );
    }
    return 0;
}

static
int
output_random( enum output_type type
, int n
, int decor
){  switch(type)
    { case ty_ascii:
            if( output_random_single_range( type, n, decor, 0x21, 0x7e ))
                return ~0;
            break;
      case ty_lascii:
            if( output_random_single_range( type, n, decor, 'A', 'Z' ))
                return ~0;
            break;
      case ty_uascii:
            if( output_random_single_range( type, n, decor, 'a', 'z' ))
                return ~0;
            break;
      case ty_anum:
        {   unsigned range = ( '9' - '0' + 1 ) + ( 'Z' - 'A' + 1 ) + ( 'z' - 'a' + 1 );
            unsigned bits = bits_in_range( 0, range - 1 );
            if( E_random_I_prepare_data( n * bits ))
                return ~0;
            while( n-- )
            {   unsigned char c = E_random_R_bits(bits);
                c += '0';
                if( c > '9' )
                {   c = c - ( '9' + 1 ) + 'A';
                    if( c > 'Z' )
                    {   c = c - ( 'Z' + 1 ) + 'a';
                        if( c > 'z' )
                        {   c = c - ( 'z' + 1 ) + '0';
                            if( c > '9' )
                            {   c = c - ( '9' + 1 ) + 'A';
                                if( c > 'Z' )
                                    c = c - ( 'Z' + 1 ) + 'a';
                            }
                        }
                    }
                }
                cputc( c, decor );
            }
            break;
        }
      case ty_lcase:
        {   unsigned range = ( '9' - '0' + 1 ) + ( 'z' - 'a' + 1 );
            unsigned bits = bits_in_range( 0, range - 1 );
            if( E_random_I_prepare_data( n * bits ))
                return ~0;
            while( n-- )
            {   unsigned char c = E_random_R_bits(bits);
                c += '0';
                if( c > '9' )
                {   c = c - ( '9' + 1 ) + 'a';
                    if( c > 'z' )
                    {   c = c - ( 'z' + 1 ) + '0';
                        if( c > '9' )
                            c = c - ( '9' + 1 ) + 'a';
                    }
                }
                cputc( c, decor );
            }
            break;
        }
      case ty_ucase:
        {   unsigned range = ( '9' - '0' + 1 ) + ( 'Z' - 'A' + 1 );
            unsigned bits = bits_in_range( 0, range - 1 );
            if( E_random_I_prepare_data( n * bits ))
                return ~0;
            while( n-- )
            {   unsigned char c = E_random_R_bits(bits);
                c += '0';
                if( c > '9' )
                {   c = c - ( '9' + 1 ) + 'A';
                    if( c > 'Z' )
                    {   c = c - ( 'Z' + 1 ) + '0';
                        if( c > '9' )
                            c = c - ( '9' + 1 ) + 'A';
                    }
                }
                cputc( c, decor );
            }
            break;
        }
      case ty_alpha:
        {   unsigned range = ( 'Z' - 'A' + 1 ) + ( 'z' - 'a' + 1 );
            unsigned bits = bits_in_range( 0, range - 1 );
            if( E_random_I_prepare_data( n * bits ))
                return ~0;
            while( n-- )
            {   unsigned char c = E_random_R_bits(bits);
                c += 'A';
                if( c > 'Z' )
                {   c = c - ( 'Z' + 1 ) + 'a';
                    if( c > 'z' )
                    {   c = c - ( 'z' + 1 ) + 'A';
                        if( c > 'Z' )
                            c = c - ( 'Z' + 1 ) + 'a';
                    }
                }
                cputc( c, decor );
            }
            break;
        }
      case ty_alcase:
            if( output_random_single_range( type, n, decor, 'a', 'z' ))
                return ~0;
            break;
      case ty_aucase:
            if( output_random_single_range( type, n, decor, 'A', 'Z' ))
                return ~0;
            break;
      case ty_hex:
        {   if( E_random_I_prepare_data( n * 4 ))
                return ~0;
            while( n-- )
                printf( "%01x", E_random_R_bits(4) );
            break;
        }
      case ty_uhex:
        {   if( E_random_I_prepare_data( n * 4 ))
                return ~0;
            while( n-- )
                printf( "%01X", E_random_R_bits(4) );
            break;
        }
      case ty_dec:
            if( output_random_single_range( type, n, decor, '0', '9' ))
                return ~0;
            break;
      case ty_oct:
            if( output_random_single_range( type, n, decor, '0', '7' ))
                return ~0;
            break;
      case ty_binary:
            if( output_random_single_range( type, n, decor, '0', '1' ))
                return ~0;
            break;
      case ty_ip:
        {   unsigned bits = bits_in_range( 0, 255 );
            if( E_random_I_prepare_data( n * bits ))
                return ~0;
            unsigned n_ = n;
            while( n_-- )
            {   unsigned char c = E_random_R_bits(bits);
                if( !n_ )
                    if( !c )
                        c == 1;
                    else if( c > 254 )
                        c = c - ( 254 + 1 ) + 1;
                else if( n_ == n - 1 )
                    if( !c )
                        c == 1;
                printf( "%u", c );
                if( n_ )
                    putchar( '.' );
            }
            break;
        }
      case ty_mac:
        {   if( E_random_I_prepare_data( n * 8 ))
                return ~0;
            while( n-- )
            {   printf( "%02x", E_random_R_bits(8) );
                if(n)
                    putchar( ':' );
            }
            break;
        }
      case ty_umac:
        {   if( E_random_I_prepare_data( n * 8 ))
                return ~0;
            while( n-- )
            {   printf( "%02X", E_random_R_bits(8) );
                if(n)
                    putchar( ':' );
            }
            break;
        }
      case ty_uuid:
        {   if( E_random_I_prepare_data( 16 * 8 ))
                return ~0;
            printf( "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x", E_random_R_bits(8), E_random_R_bits(8), E_random_R_bits(8), E_random_R_bits(8), E_random_R_bits(8), E_random_R_bits(8), E_random_R_bits(8), E_random_R_bits(8), E_random_R_bits(8), E_random_R_bits(8), E_random_R_bits(8), E_random_R_bits(8), E_random_R_bits(8), E_random_R_bits(8), E_random_R_bits(8), E_random_R_bits(8) );
            break;
        }
      case ty_uuuid:
        {   if( E_random_I_prepare_data( 16 * 8 ))
                return ~0;
            printf( "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X", E_random_R_bits(8), E_random_R_bits(8), E_random_R_bits(8), E_random_R_bits(8), E_random_R_bits(8), E_random_R_bits(8), E_random_R_bits(8), E_random_R_bits(8), E_random_R_bits(8), E_random_R_bits(8), E_random_R_bits(8), E_random_R_bits(8), E_random_R_bits(8), E_random_R_bits(8), E_random_R_bits(8), E_random_R_bits(8) );
            break;
        }
    }
}


int main(int argc, char *argv[])
{
  int opt;
  int n = 8;		/* Characters wanted */
  int decor = 0;		/* Precede hex numbers with 0x, oct with 0 */
  int monocase = 0;		/* 1 for lower, 2 for upper */
  enum output_type type = ty_ascii;
  int i;

    E_main_S_program = argv[0];
    _Bool type_selected = false;
    while(( opt = getopt_long(argc, argv, short_options, long_options, NULL)) != EOF )
        switch(opt)
        { case OPT_ASCII:		/* ASCII */
                if( type_selected )
                    usage(1);
                type_selected = true;
                break;
          case 'a':			    /* Alphanum only */
                if( type_selected )
                    usage(1);
                type_selected = true;
                type = ty_anum;
                break;
          case 'l':			    /* Lower case alphanum */
                if( type_selected )
                    usage(1);
                type_selected = true;
                type = ty_lcase;
                break;
          case 'u':			    /* Upper case alphanum */
                if( type_selected )
                    usage(1);
                type_selected = true;
                type = ty_ucase;
                break;
          case 'x':			    /* Hexadecimal number */
                if( type_selected )
                    usage(1);
                type_selected = true;
                type = ty_hex;
                break;
          case 'X':			    /* Upper case hex number */
                if( type_selected )
                    usage(1);
                type_selected = true;
                type = ty_uhex;
                break;
          case 'd':			    /* Decimal number */
                if( type_selected )
                    usage(1);
                type_selected = true;
                type = ty_dec;
                break;
          case 'o':			    /* Octal number */
                if( type_selected )
                    usage(1);
                type_selected = true;
                type = ty_oct;
                break;
          case 'b':		     	/* Binary number (for Bynar saboteurs) */
                if( type_selected )
                    usage(1);
                type_selected = true;
                type = ty_binary;
                break;
          case 'A':			    /* Alphabetic */
                if( type_selected )
                    usage(1);
                type_selected = true;
                type = ty_alpha;
                break;
          case 'L':			    /* Lower case alphabetic */
                if( type_selected )
                    usage(1);
                type_selected = true;
                type = ty_alcase;
                break;
          case 'U':			    /* Upper case alphabetic */
                if( type_selected )
                    usage(1);
                type_selected = true;
                type = ty_aucase;
                break;
          case 'i':			    /* IP address suffix */
                if( type_selected )
                    usage(1);
                type_selected = true;
                type = ty_ip;
                n = 4;
                break;
          case 'm':			    /* Lower case MAC address */
                if( type_selected )
                    usage(1);
                type_selected = true;
                type = ty_mac;
                n = 6;
                break;
          case 'M':			    /* Upper case MAC address */
                if( type_selected )
                    usage(1);
                type_selected = true;
                type = ty_umac;
                n = 6;
                break;
          case 'g':			    /* UUID/GUID */
                if( type_selected )
                    usage(1);
                type_selected = true;
                type = ty_uuid;
                break;
          case 'G':			    /* UUID/GUID */
                if( type_selected )
                    usage(1);
                type_selected = true;
                type = ty_uuuid;
                break;
          case 's':		        /* Use /dev/random, not /dev/urandom */
                E_random_S_secure_source = true;
                break;
          case 'c':			    /* C constant */
                decor = 1;
                break;
          case OPT_LOWER:		/* --lower */
                monocase = 1;
                break;
          case OPT_UPPER:		/* --upper */
                monocase = 2;
                break;
          case 'h':
                usage(0);
                break;
          case 'V':
                printf( "%s %s\n", PACKAGE_NAME, PACKAGE_VERSION );
                exit(0);
          default:
                usage(1);
                break;
        }
    if( optind != argc )
    {   if( optind + 1 != argc )
            usage(1);
        n = atoi( argv[optind] );
        if( !n
        || ( type == ty_ip
          && n > 4
        )
        || (( type == ty_mac
            || type == ty_umac
          )
          && n > 6
        )
        || type == ty_uuid
        || type == ty_uuuid
        )
            usage(1);
    }
    E_random_M();
    /* Adjust type for monocasing */
    if(monocase)
        switch(type)
        { case ty_ascii:
          case ty_anum:
          case ty_alpha:
                type += monocase;
                break;
          case ty_hex:
          case ty_mac:
          case ty_uuid:
                type += monocase-1;
                break;
        }
    if(decor)
        switch(type)
        { case ty_hex:
          case ty_uhex:
                putchar('0');
                putchar('x');
                break;
          case ty_oct:
                putchar('0');
                break;
          case ty_dec:
                /* Do nothing - handled later */
                break;
          default:
                putchar('\"');
                break;
        }
    output_random(type, n, decor);
    if(decor)
        switch(type)
        { case ty_hex:
          case ty_uhex:
          case ty_oct:
          case ty_dec:
                /* Do nothing */
                break;
          default:
                putchar('\"');
                break;
        }
    putchar('\n');
    return 0;
}
