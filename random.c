
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
static
int
E_random_I_prepare_data_I( size_t bits
, size_t rand_bits
, size_t *all_bits
, size_t *new_rands
){  size_t new_bits = bits - ( E_random_S_n_bits - E_random_S_i_bit );
    new_bits = J_align_up( new_bits, rand_bits );
    *all_bits = new_bits + ( E_random_S_n_bits - E_random_S_i_bit );
    size_t bytes = *all_bits / 8 + ( *all_bits % 8 ? 1 : 0 );
    unsigned char *data = realloc( E_random_S_data, bytes );
    if( !data )
        return ~0;
    E_random_S_data = data;
    if( E_random_S_n_bits - E_random_S_i_bit ) // Przeniesienie pozostałych danych na koniec.
        if( new_bits < E_random_S_i_bit
        || new_bits >= E_random_S_n_bits
        ) // Kopiując od początku.
        {   size_t dst = new_bits / 8;
            size_t src = E_random_S_i_bit / 8;
            unsigned dst_bits = J_min( 8 - new_bits % 8, E_random_S_n_bits - E_random_S_i_bit );
            unsigned src_bits = ( E_random_S_n_bits - 1 ) / 8 != E_random_S_i_bit / 8
            ? 8 - E_random_S_i_bit % 8
            : E_random_S_n_bits - E_random_S_i_bit;
            if(( E_random_S_n_bits - 1 ) / 8 == E_random_S_i_bit / 8 )
                data[dst] = data[src] >> ( E_random_S_i_bit % 8 ) << ( new_bits % 8 );
            else if( dst_bits > src_bits )
            {   data[dst] = ( data[src] >> ( 8 - src_bits )) << ( new_bits % 8 );
                src++;
                data[dst] |= ( data[src] & J_mask( dst_bits - src_bits )) << ( new_bits % 8 + src_bits );
            }else
            {   data[dst] = ( data[src] >> ( src_bits - dst_bits )) << ( new_bits % 8 );
                if( dst_bits == src_bits )
                    src++;
            }
            E_random_S_i_bit += dst_bits;
            while( E_random_S_i_bit != E_random_S_n_bits )
            {   dst++;
                unsigned dst_bits = J_min( 8, E_random_S_n_bits - E_random_S_i_bit );
                unsigned src_bits = 8 - E_random_S_i_bit % 8;
                if( dst_bits > src_bits )
                {   data[dst] = data[src] << ( 8 - src_bits );
                    src++;
                    data[dst] |= data[src] & J_mask( dst_bits - src_bits );
                }else
                {   data[dst] = data[src] >> ( src_bits - dst_bits );
                    if( dst_bits == src_bits )
                        src++;
                }
                E_random_S_i_bit += dst_bits;
            }
        }else // Kopiując od końca.
        {   size_t dst = bytes - 1;
            size_t src = ( E_random_S_n_bits - 1 ) / 8;
            unsigned dst_bits = ( E_random_S_n_bits - 1 ) / 8 != E_random_S_i_bit / 8
            ? *all_bits % 8
            : E_random_S_n_bits - E_random_S_i_bit;
            unsigned src_bits = E_random_S_n_bits
            - (( E_random_S_n_bits - 1 ) / 8 != E_random_S_i_bit / 8
              ? J_align_down( E_random_S_n_bits - 1, 8 )
              : E_random_S_i_bit
              );
            if(( E_random_S_n_bits - 1 ) / 8 == E_random_S_i_bit / 8 )
                data[dst] = data[src] >> ( E_random_S_i_bit % 8 );
            else if( dst_bits > src_bits )
            {   data[dst] = data[src] << ( dst_bits - src_bits );
                src--;
                data[dst] |= data[src] >> ( 8 - ( dst_bits - src_bits ));
            }else
            {   data[dst] = data[src] >> ( src_bits - dst_bits );
                if( dst_bits == src_bits )
                    src--;
            }
            while( E_random_S_n_bits != E_random_S_i_bit )
            {   dst--;
                unsigned dst_bits = J_min( 8, E_random_S_n_bits - E_random_S_i_bit );
                unsigned src_bits = E_random_S_n_bits - J_align_down( E_random_S_n_bits - 1, 8 );
                if( dst_bits > src_bits )
                {   data[dst] = data[src] << ( dst_bits - src_bits );
                    src--;
                    data[dst] |= data[src] >> ( 8 - ( dst_bits - src_bits ));
                }else
                {   data[dst] = data[src] >> ( src_bits - dst_bits );
                    if( dst_bits == src_bits )
                        src--;
                }
                E_random_S_n_bits -= dst_bits;
            }
        }
    *new_rands = new_bits / rand_bits;
}
int
E_random_I_prepare_data( size_t bits
){  if( bits > E_random_S_n_bits - E_random_S_i_bit )
    {   size_t all_bits;
        if( ~E_random_S_random_fd )
        {   size_t new_rands;
            E_random_I_prepare_data_I( bits, 8, &all_bits, &new_rands );
            unsigned char *data = E_random_S_data;
            do
            {   int i = read( E_random_S_random_fd, data, new_rands );
                if( !~i )
                    return i;
                new_rands -= i;
                data += i;
            }while( new_rands );
        }else
        {   unsigned rand_bits = sizeof(unsigned) * 8 - __builtin_clz( RAND_MAX );
            if( RAND_MAX ^ J_mask( rand_bits ))
                rand_bits >>= 1;
            size_t new_rands;
            E_random_I_prepare_data_I( bits, rand_bits, &all_bits, &new_rands );
            unsigned char *data = E_random_S_data;
            do
            {   int d = rand();
                for( unsigned i = 0; i < rand_bits; i += 8 )
                {   if( new_rands != 1
                    || i + 8 < rand_bits
                    )
                        *data = ( unsigned char )( d >> i );
                    else
                        *data = ( *data & ~J_mask(i) ) | ( unsigned char )( d >> i );
                    data++;
                }
            }while( --new_rands );
        }
        E_random_S_n_bits = all_bits;
        E_random_S_i_bit = 0;
    }
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
