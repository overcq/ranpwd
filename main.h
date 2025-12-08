#ifndef MAIN_H
#define MAIN_H
#define J_a_R_n(a)              ( sizeof(a) / sizeof( (a)[0] ))
#define J_min(a,b)              ( (a) < (b) ? (a) : (b) )
#define J_mask(bits)            (( 1UL << (bits) ) - 1 )
#define J_align_down(v,align)   (( (v) / (align) ) * (align) )
#define J_align_up(v,align)     ((( (v) + (align) - 1 ) / (align) ) * (align) )
#endif
