/******************************************************************************/
#include <assert.h>
#include <ctype.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include "main.h"
//==============================================================================
extern const char *E_main_S_program;
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
_Bool E_random_S_secure_source;     /* true if we should use /dev/random */
static int E_random_S_random_fd;
static unsigned char *E_random_S_data;
static size_t E_random_S_n_bits;
static size_t E_random_S_i_bit;
//==============================================================================
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
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
static
int
E_random_I_prepare_data_I( size_t bits
, size_t rand_bits
, size_t *new_rands
){  size_t new_bits = bits > E_random_S_n_bits - E_random_S_i_bit ? bits - ( E_random_S_n_bits - E_random_S_i_bit ) : 0;
    new_bits = J_align_up( new_bits, rand_bits );
    size_t all_bits = new_bits + ( E_random_S_n_bits - E_random_S_i_bit );
    size_t bytes = all_bits / 8 + ( all_bits % 8 ? 1 : 0 );
    unsigned char *data;
    _Bool realloc_after_move = false;
    if( bytes > E_random_S_n_bits / 8 + ( E_random_S_n_bits % 8 ? 1 : 0 ))
    {   data = realloc( E_random_S_data, bytes );
        if( !data )
            return ~0;
        E_random_S_data = data;
    }else
    {   data = E_random_S_data;
        realloc_after_move = bytes < E_random_S_n_bits / 8 + ( E_random_S_n_bits % 8 ? 1 : 0 );
    }
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
            ? all_bits % 8
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
    if( realloc_after_move )
    {   data = realloc( E_random_S_data, bytes );
        if( !data )
            return ~0;
        E_random_S_data = data;
    }
    *new_rands = new_bits / rand_bits;
    E_random_S_n_bits = all_bits;
    E_random_S_i_bit = 0;
    return 0;
}
int
E_random_I_prepare_data( size_t bits
){  if( bits > E_random_S_n_bits - E_random_S_i_bit )
        if( ~E_random_S_random_fd )
        {   size_t new_rands;
            if( E_random_I_prepare_data_I( bits, 8, &new_rands ))
                return ~0;
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
            if( rand_bits < 8 )
                return ~0;
            size_t new_rands;
            if( E_random_I_prepare_data_I( bits, rand_bits, &new_rands ))
                return ~0;
            if( new_rands )
            {   unsigned char *data = E_random_S_data;
                size_t i_bit = 0;
                *data = 0;
                do
                {   unsigned d = rand();
                    for( unsigned i = 0; i < rand_bits; i += 8 )
                    {   *data |= (( d >> i ) & J_mask( 8 - i_bit % 8 )) << ( i_bit % 8 );
                        if( new_rands != 1 )
                        {   if( i + 8 < rand_bits ) // Jeżeli nie ostatni bajt z rand.
                                *++data = i_bit % 8 ? ( d >> ( i + 8 - i_bit % 8 )) & J_mask( i_bit % 8 ) : 0;
                            else if( i_bit % 8 )
                                *++data = ( i_bit + rand_bits ) % 8 ? ( d >> ( i + 8 - i_bit % 8 )) & J_mask(( i_bit + rand_bits ) % 8 ) : 0;
                        }else
                            if( i + 8 < rand_bits )
                                *++data = i_bit % 8 ? ( d >> ( i + 8 - i_bit % 8 )) & J_mask( i_bit % 8 ) : 0;
                            else if(( i_bit + rand_bits ) % 8 )
                            {   data++;
                                *data = ( *data & ~J_mask(( i_bit + rand_bits ) % 8 )) | (( d >> i ) & J_mask(( i_bit + rand_bits ) % 8 ));
                            }
                    }
                    i_bit += rand_bits;
                }while( --new_rands );
            }
        }
    return 0;
}
unsigned
E_random_R_bits( unsigned bits
){  assert( bits > 0 && bits <= sizeof(unsigned) * 8 && E_random_S_i_bit + bits <= E_random_S_n_bits );
    size_t byte_i = E_random_S_i_bit / 8;
    unsigned bits_i = E_random_S_i_bit % 8;
    unsigned d = 0;
    for( unsigned i = 0; i != sizeof(unsigned); i++ )
    {   d |= ( E_random_S_data[ byte_i + i ] >> bits_i ) << i * 8;
        if( bits > i * 8 + 8 - bits_i )
            break;
        d |= E_random_S_data[ byte_i + i + 1 ] << ( i * 8 + 8 - bits_i );
    }
    E_random_S_i_bit += bits;
    return d & J_mask(bits);
}
/******************************************************************************/