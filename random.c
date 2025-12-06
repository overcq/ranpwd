
#include <assert.h>
#include <ctype.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include "main.h"

extern const char *E_main_S_program;

_Bool E_random_S_secure_source;     /* true if we should use /dev/random */
static int E_random_S_random_fd;
static unsigned char *E_random_S_data;
static size_t E_random_S_n_bits;
static size_t E_random_S_i_bit;

void
E_random_M( void
){  E_random_S_random_fd = open( E_random_S_secure_source ? "/dev/random" : "/dev/urandom", O_RDONLY );
    if( !~E_random_S_random_fd )
	{   if( E_random_S_secure_source )
	    {   fprintf( stderr, "%s: cannot open /dev/random\n", E_main_S_program );
            exit(1);
	    }
        else
            fprintf( stderr, "%s: warning: cannot open /dev/urandom\n", E_main_S_program );
        time_t t;
        time( &t );
        pid_t pid = getpid();
        srand( t ^ pid );		/* As secure as we can get... */
	}
}
int
E_random_I_prepare_data( size_t bits
){  if( bits > E_random_S_n_bits - E_random_S_i_bit )
        if( ~E_random_S_random_fd )
        {   size_t bytes = bits / 8 + ( bits % 8 ? 1 : 0 );
            size_t all_bits;
            if( E_random_S_n_bits - E_random_S_i_bit )
            {   if( bits % 8 > ( E_random_S_n_bits - E_random_S_i_bit ) % 8 ) // Jeśli nie wystarczy reszty bitów w bajcie, to trzeba przygotować jeden bajt więcej danych.
                {   all_bits = bytes * 8 + ( E_random_S_n_bits - E_random_S_i_bit ) % 8;
                    bytes++;
                }else
                    all_bits = J_align_down( bits, 8 ) + ( E_random_S_n_bits - E_random_S_i_bit ) % 8;
            }else
                all_bits = bytes * 8;
            unsigned char *data = realloc( E_random_S_data, bytes );
            if( !data )
                return ~0;
            E_random_S_data = data;
            size_t new_bits = bits - ( E_random_S_n_bits - E_random_S_i_bit );
            if( E_random_S_n_bits - E_random_S_i_bit ) // Przeniesienie pozostałych danych na koniec do początku bajtu.
            {   size_t dst = bytes - 1;
                size_t src = ( E_random_S_n_bits - 1 ) / 8;
                unsigned dst_bits = ( bits - 1 ) % 8 + 1;
                unsigned src_bits = E_random_S_n_bits
                - (( E_random_S_n_bits - 1 ) % 8 != E_random_S_i_bit % 8
                  ? J_align_down( E_random_S_n_bits - 1, 8 )
                  : E_random_S_i_bit % 8
                  );
                if(( E_random_S_n_bits - 1 ) % 8 == E_random_S_i_bit % 8 )
                    data[dst] = data[src] >> ( E_random_S_i_bit % 8 );
                else if( src_bits == dst_bits )
                    data[dst] = data[src];
                else if( src_bits > dst_bits )
                    data[dst] = data[src] >> ( src_bits - dst_bits );
                else
                {   data[dst] = data[src] << ( dst_bits - src_bits );
                    src--;
                    data[dst] |= data[src] >> ( 8 - ( dst_bits - src_bits ));
                }
                E_random_S_n_bits -= dst_bits;
                while( E_random_S_n_bits )
                {   dst--;
                    unsigned dst_bits = 8;
                    unsigned src_bits = E_random_S_n_bits - J_align_down( E_random_S_n_bits - 1, 8 );
                    if( src_bits == dst_bits )
                        data[dst] = data[src];
                    else if( src_bits > dst_bits )
                        data[dst] = data[src] >> ( src_bits - dst_bits );
                    else
                    {   data[dst] = data[src] << ( dst_bits - src_bits );
                        src--;
                        data[dst] |= data[src] >> ( 8 - ( dst_bits - src_bits ));
                    }
                    E_random_S_n_bits -= dst_bits;
                }
            }
            size_t new_bytes = new_bits / 8 + ( new_bits % 8 ? 1 : 0 );
            do
            {   int i = read( E_random_S_random_fd, data, new_bytes );
                if( !~i )
                    return i;
                new_bytes -= i;
                data += i;
            }while( new_bytes );
            E_random_S_n_bits = all_bits;
            E_random_S_i_bit = 0;
        }/*else //TODO Zmienić na wybieranie bitowe.
        {   if( bits > E_random_S_n_bits - E_random_S_i_bit )
            {   data = realloc( E_random_S_data, bits / 8 + ( bits % 8 ? 1 : 0 ));
                if( !data )
                    return ~0;
                E_random_S_data = data;
            }else
                data = E_random_S_data;
            size_t new_bits = bits - ( E_random_S_n_bits - E_random_S_i_bit );
            size_t new_bytes = new_bits / 8 + ( new_bits % 8 ? 1 : 0 );
            if( RAND_MAX >= ( 2U << 16 ) - 1 )
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
        }*/
    return 0;
}
unsigned char
E_random_R_bits( unsigned bits
){  assert( bits > 0 && bits <= 8 && E_random_S_i_bit + bits <= E_random_S_n_bits );
    size_t byte_i = E_random_S_i_bit / 8;
    unsigned bits_i = E_random_S_i_bit % 8;
    unsigned char c = ( E_random_S_data[ byte_i ] >> bits_i ) & J_mask( J_min( bits, 8 - bits_i ));
    if( bits > 8 - bits_i )
        c |= ( E_random_S_data[ byte_i + 1 ] & J_mask( bits - ( 8 - bits_i ))) << ( 8 - bits_i );
    E_random_S_i_bit += bits;
    return c;
}
