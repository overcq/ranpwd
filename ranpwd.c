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

/*
 * ranpwd.c: Generate random passwords using the Linux kernel-based true
 *           random number generator (if available.)
 */

#include "config.h"

#include <stdbool.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif

static int ran_fd;		    /* /dev/(u)random file descriptor if avail. */
static int secure_source;	/* 1 if we should use /dev/random */
const char *program;

enum extended_options {
  OPT_UPPER = 256,
  OPT_LOWER,
  OPT_ASCII,
};

static const char *short_options = "aluxXdobALUimgGMschV";
#ifdef HAVE_GETOPT_LONG
const struct option long_options[] = {
  { "ascii",            0, 0, OPT_ASCII },
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
  { "ip",               0, 0, 'i' },
  { "mac-address",      0, 0, 'm' },
  { "guid",             0, 0, 'g' },
  { "uuid",             0, 0, 'g' },
  { "uc-guid",          0, 0, 'G' },
  { "uc-uuid",          0, 0, 'G' },
  { "secure",           0, 0, 's' },
  { "c",		0, 0, 'c' },
  { "help",             0, 0, 'h' },
  { "version",          0, 0, 'V' },
  { 0, 0, 0, 0 }
};
# define LO(X) X
#else
# define getopt_long(C,V,O,L,I) getopt(C,V,O)
# define LO(X)
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
	  LO("  --version            ")"  -v  Display program version\n"
	  , PACKAGE_NAME, PACKAGE_VERSION, program);
  exit(err);
}

/*
 * setrandom(): Attempt to open /dev/(u)random if available, otherwise call
 *              srand()
 */
static void setrandom(void)
{   ran_fd = open( secure_source ? "/dev/random" : "/dev/urandom", O_RDONLY );
    if( !~ran_fd )
	{   if( secure_source )
	    {   fprintf(stderr, "%s: cannot open /dev/random\n", program);
            exit(1);
	    }
        else
            fprintf(stderr, "%s: warning: cannot open /dev/urandom\n", program);
        time_t t;
        time( &t );
        pid_t pid = getpid();
        srand( t ^ pid );		/* As secure as we can get... */
	}
}

/*
 * getrandom(): Get random bytes
 */
static
int
getrandom( unsigned char **buf
, size_t n
){  unsigned char *buf_ = malloc(n);
    if( !buf_ )
        return ~0;
    *buf = buf_;
    if( ~ran_fd )
        while(n)
        {   int i = read( ran_fd, buf_, n );
            if( !~i )
            {   free( *buf );
                return i;
            }
            n -= i;
            buf_ += n;
        }
    else
    {   if( RAND_MAX >= ( 2U << 16 ) - 1 )
        {   _Bool half = n % 2;
            n /= 2;
            while( n-- )
            {   *( unsigned short * )buf_ = ( unsigned short )rand();
                buf_ += 2;
            }
            if(half)
                *buf_ = ( unsigned char )rand();
        }else
            while( n-- )
                *buf_++ = ( unsigned char )rand();
    }  
    return 0;
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
){  return sizeof(unsigned) * 8 - __builtin_clz( max - min + 1 );
}

static
int
output_random_single_range( enum output_type type
, int n
, int decor
, unsigned char min
, unsigned char max
){  unsigned bits = bits_in_range( min, max );
    unsigned bytes = n * bits;
    bytes = bytes / 8 + ( n % 8 ? 1 : 0 );
    unsigned char *buf, *buf_;
    if( getrandom( &buf, bytes ))
        return ~0;
    buf_ = buf;
    unsigned i = 0;
    while( n-- )
    {   unsigned char c = ( *buf_ >> i ) & (( 1 << bits ) - 1 );
        if( bits > 8 - i )
        {   c |= ( *++buf_ & (( 1 << ( bits - ( 8 - i ))) - 1 )) << ( 8 - i );
            i = bits - ( 8 - i );
        }else
            i += bits;
        c += min;
        if( c > max )
            c = c - ( max + 1 ) + min;
        cputc( c, decor );
    }
    free(buf);
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
            unsigned bits = bits_in_range( 0, range );
            unsigned bytes = n * bits;
            bytes = bytes / 8 + ( n % 8 ? 1 : 0 );
            unsigned char *buf, *buf_;
            if( getrandom( &buf, bytes ))
                return ~0;
            buf_ = buf;
            unsigned i = 0;
            while( n-- )
            {   unsigned char c = ( *buf_ >> i ) & (( 1 << bits ) - 1 );
                if( bits > 8 - i )
                {   c |= ( *++buf_ & (( 1 << ( bits - ( 8 - i ))) - 1 )) << ( 8 - i );
                    i = bits - ( 8 - i );
                }else
                    i += bits;
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
            free(buf);
            break;
        }
      case ty_lcase:
        {   unsigned range = ( '9' - '0' + 1 ) + ( 'z' - 'a' + 1 );
            unsigned bits = bits_in_range( 0, range );
            unsigned bytes = n * bits;
            bytes = bytes / 8 + ( n % 8 ? 1 : 0 );
            unsigned char *buf, *buf_;
            if( getrandom( &buf, bytes ))
                return ~0;
            buf_ = buf;
            unsigned i = 0;
            while( n-- )
            {   unsigned char c = ( *buf_ >> i ) & (( 1 << bits ) - 1 );
                if( bits > 8 - i )
                {   c |= ( *++buf_ & (( 1 << ( bits - ( 8 - i ))) - 1 )) << ( 8 - i );
                    i = bits - ( 8 - i );
                }else
                    i += bits;
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
            free(buf);
            break;
        }
      case ty_ucase:
        {   unsigned range = ( '9' - '0' + 1 ) + ( 'Z' - 'A' + 1 );
            unsigned bits = bits_in_range( 0, range );
            unsigned bytes = n * bits;
            bytes = bytes / 8 + ( n % 8 ? 1 : 0 );
            unsigned char *buf, *buf_;
            if( getrandom( &buf, bytes ))
                return ~0;
            buf_ = buf;
            unsigned i = 0;
            while( n-- )
            {   unsigned char c = ( *buf_ >> i ) & (( 1 << bits ) - 1 );
                if( bits > 8 - i )
                {   c |= ( *++buf_ & (( 1 << ( bits - ( 8 - i ))) - 1 )) << ( 8 - i );
                    i = bits - ( 8 - i );
                }else
                    i += bits;
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
            free(buf);
            break;
        }
      case ty_alpha:
        {   unsigned range = ( 'Z' - 'A' + 1 ) + ( 'z' - 'a' + 1 );
            unsigned bits = bits_in_range( 0, range );
            unsigned bytes = n * bits;
            bytes = bytes / 8 + ( n % 8 ? 1 : 0 );
            unsigned char *buf, *buf_;
            if( getrandom( &buf, bytes ))
                return ~0;
            buf_ = buf;
            unsigned i = 0;
            while( n-- )
            {   unsigned char c = ( *buf_ >> i ) & (( 1 << bits ) - 1 );
                if( bits > 8 - i )
                {   c |= ( *++buf_ & (( 1 << ( bits - ( 8 - i ))) - 1 )) << ( 8 - i );
                    i = bits - ( 8 - i );
                }else
                    i += bits;
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
            free(buf);
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
        {   unsigned r = n % 2;
            n /= 2;
            unsigned char *buf, *buf_;
            if( getrandom( &buf, n ))
                return ~0;
            buf_ = buf;
            while( n-- )
            {   printf( "%02x", *buf_ );
                buf_++;
            }
            if(r)
                printf( "%01x", *buf_ );
            free(buf);
            break;
        }
      case ty_uhex:
        {   unsigned r = n % 2;
            n /= 2;
            unsigned char *buf, *buf_;
            if( getrandom( &buf, n ))
                return ~0;
            buf_ = buf;
            while( n-- )
            {   printf( "%02X", *buf_ );
                buf_++;
            }
            if(r)
                printf( "%01X", *buf_ );
            free(buf);
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
            unsigned bytes = n * bits;
            bytes = bytes / 8 + ( n % 8 ? 1 : 0 );
            unsigned char *buf, *buf_;
            if( getrandom( &buf, bytes ))
                return ~0;
            buf_ = buf;
            unsigned i = 0, n_ = n;
            while( n_-- )
            {   unsigned char c = ( *buf_ >> i ) & (( 1 << bits ) - 1 );
                if( bits > 8 - i )
                {   c |= ( *++buf_ & (( 1 << ( bits - ( 8 - i ))) - 1 )) << ( 8 - i );
                    i = bits - ( 8 - i );
                }else
                    i += bits;
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
            free(buf);
            break;
        }
      case ty_mac:
        {   unsigned char *buf, *buf_;
            if( getrandom( &buf, n ))
                return ~0;
            buf_ = buf;
            while( n-- )
            {   printf( "%02x", *buf_ );
                buf_++;
                if(n)
                    putchar( ':' );
            }
            free(buf);
            break;
        }
      case ty_umac:
        {   unsigned char *buf, *buf_;
            if( getrandom( &buf, n ))
                return ~0;
            buf_ = buf;
            while( n-- )
            {   printf( "%02X", *buf_ );
                buf_++;
                if(n)
                    putchar( ':' );
            }
            free(buf);
            break;
        }
      case ty_uuid:
        {   unsigned char *buf;
            if( getrandom( &buf, 16 ))
                return ~0;
            printf( "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x", buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], buf[8], buf[9], buf[1], buf[11], buf[12], buf[13], buf[14], buf[15] );
            free(buf);
            break;
        }
      case ty_uuuid:
        {   unsigned char *buf;
            if( getrandom( &buf, 16 ))
                return ~0;
            printf( "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X", buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], buf[8], buf[9], buf[1], buf[11], buf[12], buf[13], buf[14], buf[15] );
            free(buf);
            break;
        }
    }
}


int main(int argc, char *argv[])
{
  int opt;
  int nchar = 8;		/* Characters wanted */
  int decor = 0;		/* Precede hex numbers with 0x, oct with 0 */
  int monocase = 0;		/* 1 for lower, 2 for upper */
  enum output_type type = ty_ascii;
  int i;

    program = argv[0];
    _Bool type_selected = false;
    while(( opt = getopt_long(argc, argv, short_options, long_options, NULL)) != EOF )
        switch(opt)
        { case OPT_ASCII:		/* ASCII */
                if( type_selected )
                    usage(1);
                type_selected = true;
                break;
          case 'a':			/* Alphanum only */
                if( type_selected )
                    usage(1);
                type_selected = true;
                type = ty_anum;
                break;
          case 'l':			/* Lower case alphanum */
                if( type_selected )
                    usage(1);
                type_selected = true;
                type = ty_lcase;
                break;
          case 'u':			/* Upper case alphanum */
                if( type_selected )
                    usage(1);
                type_selected = true;
                type = ty_ucase;
                break;
          case 'x':			/* Hexadecimal number */
                if( type_selected )
                    usage(1);
                type_selected = true;
                type = ty_hex;
                break;
          case 'X':			/* Upper case hex number */
                if( type_selected )
                    usage(1);
                type_selected = true;
                type = ty_uhex;
                break;
          case 'd':			/* Decimal number */
                if( type_selected )
                    usage(1);
                type_selected = true;
                type = ty_dec;
                break;
          case 'o':			/* Octal number */
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
          case 'A':			/* Alphabetic */
                if( type_selected )
                    usage(1);
                type_selected = true;
                type = ty_alpha;
                break;
          case 'L':			/* Lower case alphabetic */
                if( type_selected )
                    usage(1);
                type_selected = true;
                type = ty_alcase;
                break;
          case 'U':			/* Upper case alphabetic */
                if( type_selected )
                    usage(1);
                type_selected = true;
                type = ty_aucase;
                break;
          case 'i':			/* IP address suffix */
                if( type_selected )
                    usage(1);
                type_selected = true;
                type = ty_ip;
                nchar = 4;
                break;
          case 'm':			/* Lower case MAC address */
                if( type_selected )
                    usage(1);
                type_selected = true;
                type = ty_mac;
                nchar = 6;
                break;
          case 'M':			/* Upper case MAC address */
                if( type_selected )
                    usage(1);
                type_selected = true;
                type = ty_umac;
                nchar = 6;
                break;
          case 'g':			/* UUID/GUID */
                if( type_selected )
                    usage(1);
                type_selected = true;
                type = ty_uuid;
                break;
          case 'G':			/* UUID/GUID */
                if( type_selected )
                    usage(1);
                type_selected = true;
                type = ty_uuuid;
                break;
          case 's':		       /* Use /dev/random, not /dev/urandom */
                secure_source = 1;
                break;
          case 'c':			/* C constant */
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
        nchar = atoi( argv[optind] );
        if( !nchar
        || ( type == ty_ip
          && nchar > 4
        )
        || (( type == ty_mac
            || type == ty_umac
          )
          && nchar > 6
        )
        || type == ty_uuid
        || type == ty_uuuid
        )
            usage(1);
    }
    setrandom();
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
    output_random(type, nchar, decor);
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
