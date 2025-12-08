/* ----------------------------------------------------------------------- *
 *   
 *   Copyright 1994-2008 H. Peter Anvin - All Rights Reserved
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, Inc., 51 Franklin St, Fifth Floor,
 *   Boston MA 02110-1301, USA; either version 3 of the License, or
 *   (at your option) any later version; incorporated herein by reference.
 *
 * ----------------------------------------------------------------------- */
#include "config.h"
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
//==============================================================================
enum output_type {
  ty_hard,
  ty_ascii, ty_lascii, ty_uascii,
  ty_anum, ty_lcase, ty_ucase,
  ty_alpha, ty_alcase, ty_aucase,
  ty_hex, ty_uhex,
  ty_ip,
  ty_mac, ty_umac,
  ty_uuid, ty_uuuid,
  ty_dec, ty_oct, ty_binary
};
enum extended_options {
  OPT_UPPER = 256,
  OPT_LOWER,
  OPT_ASCII,
};
struct E_main_Z_min_max
{ unsigned min, max;
};
//==============================================================================
extern _Bool E_random_S_secure_source;
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
const char *E_main_S_program;
static const char *short_options = "raluxXdobALUimgGMschV";
#ifdef HAVE_GETOPT_LONG
const struct option long_options[] = {
  { "hard",         0, 0, 'r' },
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
//==============================================================================
static void usage(int err)
{
  fprintf(stderr,
	  "%s %s\n"
	  "Usage: %s [options] [length [count]]\n"
	  LO("  --hard               " "  -r  Hard password\n")
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
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
/*
 * cputc():
 *
 * putchar(), with option to escape characters that have to be escaped in C
 */
static
void
cputc( int c
, int esc
){  if(esc)
        switch(c)
        { case '\"':
          case '\\':
          case '\'':
            putchar('\\');
        }
    putchar(c);
}
static
int
bits_in_count( unsigned count
){  return sizeof(unsigned) * 8 - __builtin_clz( count - 1 );
}
static
unsigned
E_main_I_print_I_ranges_I_bits(
  unsigned ranges_n
, struct E_main_Z_min_max ranges[]
){  unsigned count = 0;
    for( unsigned i = 0; i != ranges_n; i++ )
        count += ranges[i].max - ranges[i].min + 1;
    return bits_in_count(count);
}
static
unsigned
E_main_I_print_I_ranges_I_chars( unsigned c
, unsigned ranges_n
, struct E_main_Z_min_max ranges[]
){  unsigned i = 0;
    do
    {   c += ranges[i].min;
        if( c <= ranges[i].max )
            break;
        c -= ranges[i].max + 1;
        if( i != ranges_n - 1 )
            i++;
        else
            i = 0;
    }while(true);
    return c;
}
static
int
E_main_I_print_I_ranges( enum output_type type
, int n
, int decor
, unsigned ranges_n
, struct E_main_Z_min_max ranges[]
){  unsigned bits = E_main_I_print_I_ranges_I_bits( ranges_n, ranges );
    if( E_random_I_prepare_data( n * bits ))
        return ~0;
    do
    {   unsigned c = E_random_R_bits(bits);
        c = E_main_I_print_I_ranges_I_chars( c, ranges_n, ranges );
        cputc( c, decor );
    }while( --n );
    return 0;
}
static
int
E_main_I_print( enum output_type type
, int n
, int decor
){  switch(type)
    { case ty_hard:
        {   struct E_main_Z_min_max ranges[] =
            { 0x21, 0x2f
            , 0x3a, 0x40
            , 0x5b, 0x60
            , 0x7b, 0x7e
            };
            unsigned ranges_n = n < J_a_R_n(ranges) ? n : J_a_R_n(ranges);
            unsigned bits = E_main_I_print_I_ranges_I_bits( ranges_n, ranges );
            if( E_random_I_prepare_data(bits))
                return ~0;
            unsigned range_c[ ranges_n ];
            range_c[0] = E_random_R_bits(bits);
            range_c[0] = E_main_I_print_I_ranges_I_chars( range_c[0], ranges_n, ranges );
            unsigned ranges_n_ = ranges_n;
            if( --ranges_n_ )
            {   struct E_main_Z_min_max range = { 'A', 'Z' };
                unsigned bits = E_main_I_print_I_ranges_I_bits( 1, &range );
                if( E_random_I_prepare_data(bits))
                    return ~0;
                range_c[1] = E_random_R_bits( E_main_I_print_I_ranges_I_bits( 1, &range ));
                range_c[1] = E_main_I_print_I_ranges_I_chars( range_c[1], 1, &range );
                if( --ranges_n_ )
                {   struct E_main_Z_min_max range = { 'a', 'z' };
                    unsigned bits = E_main_I_print_I_ranges_I_bits( 1, &range );
                    if( E_random_I_prepare_data(bits))
                        return ~0;
                    range_c[2] = E_random_R_bits( E_main_I_print_I_ranges_I_bits( 1, &range ));
                    range_c[2] = E_main_I_print_I_ranges_I_chars( range_c[2], 1, &range );
                    if( --ranges_n_ )
                    {   struct E_main_Z_min_max range = { '0', '9' };
                        unsigned bits = E_main_I_print_I_ranges_I_bits( 1, &range );
                        if( E_random_I_prepare_data(bits))
                            return ~0;
                        range_c[3] = E_random_R_bits( E_main_I_print_I_ranges_I_bits( 1, &range ));
                        range_c[3] = E_main_I_print_I_ranges_I_chars( range_c[3], 1, &range );
                    }
                }
            }
            if( n > 1 )
            {   unsigned bits = 0;
                for( unsigned i = 0; i != ranges_n; i++ )
                    bits += bits_in_count( n - i );
                if( E_random_I_prepare_data(bits))
                    return ~0;
                unsigned pos[ ranges_n ];
                _Bool pos_had[ ranges_n ];
                for( unsigned i = 0; i != ranges_n; i++ )
                {   pos[i] = E_random_R_bits( bits_in_count( n - i ));
                    pos[i] = E_main_I_print_I_ranges_I_chars( pos[i], 1, &( struct E_main_Z_min_max ){ 0, n - 1 - i });
                    for( unsigned j = 0; j != ranges_n; j++ )
                        pos_had[j] = false;
                    for( unsigned j = 0; j != i; j++ )
                    {   if( pos_had[j] )
                            continue;
                        if( pos[i] >= pos[j] )
                        {   pos[i]++;
                            pos_had[j] = true;
                            j = -1;
                        }
                    }
                }
                struct E_main_Z_min_max range = { 0x21, 0x7e };
                bits = E_main_I_print_I_ranges_I_bits( 1, &range );
                if( E_random_I_prepare_data(( n - ranges_n ) * bits ))
                    return ~0;
                for( unsigned i = 0; i != n; i++ )
                {   unsigned c;
                    unsigned j;
                    for( j = 0; j != ranges_n; j++ )
                        if( pos[j] == i )
                        {   c = range_c[j];
                            break;
                        }
                    if( j == ranges_n )
                    {   c = E_random_R_bits(bits);
                        c = E_main_I_print_I_ranges_I_chars( c, 1, &range );
                    }
                    cputc( c, decor );
                }
            }else
            {   cputc( range_c[0], decor );
            }
            break;
        }
      case ty_ascii:
            if( E_main_I_print_I_ranges( type, n, decor, 1, &( struct E_main_Z_min_max ){ 0x21, 0x7e }))
                return ~0;
            break;
      case ty_lascii:
        {   struct E_main_Z_min_max ranges[] =
            { 0x21, 0x40
            , 0x5b, 0x7e
            };
            unsigned ranges_n = J_a_R_n(ranges);
            unsigned bits = E_main_I_print_I_ranges_I_bits( ranges_n, ranges );
            if( E_random_I_prepare_data( n * bits ))
                return ~0;
            do
            {   unsigned c = E_random_R_bits(bits);
                c = E_main_I_print_I_ranges_I_chars( c, ranges_n, ranges );
                cputc( c, decor );
            }while( --n );
            break;
        }
      case ty_uascii:
        {   struct E_main_Z_min_max ranges[] =
            { 0x21, 0x60
            , 0x7b, 0x7e
            };
            unsigned ranges_n = J_a_R_n(ranges);
            unsigned bits = E_main_I_print_I_ranges_I_bits( ranges_n, ranges );
            if( E_random_I_prepare_data( n * bits ))
                return ~0;
            do
            {   unsigned c = E_random_R_bits(bits);
                c = E_main_I_print_I_ranges_I_chars( c, ranges_n, ranges );
                cputc( c, decor );
            }while( --n );
            break;
        }
      case ty_anum:
        {   struct E_main_Z_min_max ranges[] =
            { '0', '9'
            , 'A', 'Z'
            , 'a', 'z'
            };
            unsigned ranges_n = J_a_R_n(ranges);
            unsigned bits = E_main_I_print_I_ranges_I_bits( ranges_n, ranges );
            if( E_random_I_prepare_data( n * bits ))
                return ~0;
            do
            {   unsigned c = E_random_R_bits(bits);
                c = E_main_I_print_I_ranges_I_chars( c, ranges_n, ranges );
                cputc( c, decor );
            }while( --n );
            break;
        }
      case ty_lcase:
        {   struct E_main_Z_min_max ranges[] =
            { '0', '9'
            , 'a', 'z'
            };
            unsigned ranges_n = J_a_R_n(ranges);
            unsigned bits = E_main_I_print_I_ranges_I_bits( ranges_n, ranges );
            if( E_random_I_prepare_data( n * bits ))
                return ~0;
            do
            {   unsigned c = E_random_R_bits(bits);
                c = E_main_I_print_I_ranges_I_chars( c, ranges_n, ranges );
                cputc( c, decor );
            }while( --n );
            break;
        }
      case ty_ucase:
        {   struct E_main_Z_min_max ranges[] =
            { '0', '9'
            , 'A', 'Z'
            };
            unsigned ranges_n = J_a_R_n(ranges);
            unsigned bits = E_main_I_print_I_ranges_I_bits( ranges_n, ranges );
            if( E_random_I_prepare_data( n * bits ))
                return ~0;
            do
            {   unsigned c = E_random_R_bits(bits);
                c = E_main_I_print_I_ranges_I_chars( c, ranges_n, ranges );
                cputc( c, decor );
            }while( --n );
            break;
        }
      case ty_alpha:
        {   struct E_main_Z_min_max ranges[] =
            { 'A', 'Z'
            , 'a', 'z'
            };
            unsigned ranges_n = J_a_R_n(ranges);
            unsigned bits = E_main_I_print_I_ranges_I_bits( ranges_n, ranges );
            if( E_random_I_prepare_data( n * bits ))
                return ~0;
            do
            {   unsigned c = E_random_R_bits(bits);
                c = E_main_I_print_I_ranges_I_chars( c, ranges_n, ranges );
                cputc( c, decor );
            }while( --n );
            break;
        }
      case ty_alcase:
            if( E_main_I_print_I_ranges( type, n, decor, 1, &( struct E_main_Z_min_max ){ 'a', 'z' }))
                return ~0;
            break;
      case ty_aucase:
            if( E_main_I_print_I_ranges( type, n, decor, 1, &( struct E_main_Z_min_max ){ 'A', 'Z' }))
                return ~0;
            break;
      case ty_hex:
        {   if( E_random_I_prepare_data( n * 4 ))
                return ~0;
            do
            {   printf( "%01x", E_random_R_bits(4) );
            }while( --n );
            break;
        }
      case ty_uhex:
        {   if( E_random_I_prepare_data( n * 4 ))
                return ~0;
            do
            {   printf( "%01X", E_random_R_bits(4) );
            }while( --n );
            break;
        }
      case ty_dec:
            if( E_main_I_print_I_ranges( type, n, decor, 1, &( struct E_main_Z_min_max ){ '0', '9' }))
                return ~0;
            break;
      case ty_oct:
            if( E_main_I_print_I_ranges( type, n, decor, 1, &( struct E_main_Z_min_max ){ '0', '7' }))
                return ~0;
            break;
      case ty_binary:
            if( E_main_I_print_I_ranges( type, n, decor, 1, &( struct E_main_Z_min_max ){ '0', '1' }))
                return ~0;
            break;
      case ty_ip:
        {   unsigned bits = E_main_I_print_I_ranges_I_bits( 1, &( struct E_main_Z_min_max ){ 0, 255 });
            if( E_random_I_prepare_data( n * bits ))
                return ~0;
            unsigned n_ = n;
            do
            {   unsigned c = E_random_R_bits(bits);
                if( n_ == 1 )
                    if( !c )
                        c == 1;
                    else if( c > 254 )
                        c = c - ( 254 + 1 ) + 1;
                else if( n_ == n )
                    if( !c )
                        c == 1;
                printf( "%u", c );
                if( n_ != 1 )
                    putchar( '.' );
            }while( --n_ );
            break;
        }
      case ty_mac:
        {   if( E_random_I_prepare_data( n * 8 ))
                return ~0;
            do
            {   printf( "%02x", E_random_R_bits(8) );
                if( n != 1 )
                    putchar( ':' );
            }while( --n );
            break;
        }
      case ty_umac:
        {   if( E_random_I_prepare_data( n * 8 ))
                return ~0;
            do
            {   printf( "%02X", E_random_R_bits(8) );
                if( n != 1 )
                    putchar( ':' );
            }while( --n );
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
int
main( int argc
, char *argv[]
){  int opt;
    int passwords = 1;
    int elements = 12;		/* Characters wanted */
    int decor = 0;		    /* Precede hex numbers with 0x, oct with 0 */
    int monocase = 0;		/* 1 for lower, 2 for upper */
    enum output_type type = ty_ascii;
    int i;

    E_main_S_program = argv[0];
    _Bool type_selected = false;
    while(( opt = getopt_long(argc, argv, short_options, long_options, NULL)) != EOF )
        switch(opt)
        { case 'r':
                if( type_selected )
                    usage(1);
                type_selected = true;
                type = ty_hard;
                break;
          case OPT_ASCII:		/* ASCII */
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
                elements = 4;
                break;
          case 'm':			    /* Lower case MAC address */
                if( type_selected )
                    usage(1);
                type_selected = true;
                type = ty_mac;
                elements = 6;
                break;
          case 'M':			    /* Upper case MAC address */
                if( type_selected )
                    usage(1);
                type_selected = true;
                type = ty_umac;
                elements = 6;
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
    {   elements = atoi( argv[optind] );
        if( !elements
        || ( type == ty_ip
          && elements > 4
        )
        || (( type == ty_mac
            || type == ty_umac
          )
          && elements > 6
        ))
            usage(1);
        if( type == ty_uuid
        || type == ty_uuuid
        )
            passwords = elements;
        optind++;
    }
    if( optind != argc )
    {   if( type == ty_uuid
        || type == ty_uuuid
        )
            usage(1);
        passwords = atoi( argv[optind] );
        if( !passwords )
            usage(1);
        optind++;
    }
    if( optind != argc )
        usage(1);
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
          default:
                usage(1);
                break;
        }
    E_random_M();
    do
    {   if(decor)
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
        E_main_I_print( type, elements, decor );
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
    }while( --passwords );
    return 0;
}
/******************************************************************************/