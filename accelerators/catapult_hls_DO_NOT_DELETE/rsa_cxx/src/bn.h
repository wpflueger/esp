#ifndef __BN_H__
#define __BN_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>

#define BN_BYTES        8
#define BN_BITS4        32
#define BN_ULONG        uint64_t

#define BN_BYTES_LG     3
#define BN_BYTES_MOD    (BN_BYTES - 1)

#define BN_BITS         (BN_BITS2 * 2)

#define BN_BITS2        (BN_BYTES * 8)
#define BN_BITS2_LG     (BN_BYTES_LG + 3)
#define BN_BITS2_MOD    ((BN_BYTES * 8) - 1)

#define BN_MASK2        (0xffffffffffffffffLL)
#define BN_MASK2l       (0x00000000ffffffffLL)
#define BN_MASK2h       (0xffffffff00000000LL)
#define BN_MASK2h1      (0xffffffff80000000LL)

#define BN_TBIT         ((BN_ULONG) 1 << (BN_BITS2 - 1))

#define MAX_BN_SIZE 200

typedef struct {

    BN_ULONG d[MAX_BN_SIZE];

    int top;                    /* Index of last used d +1. */
    /* The next are internal book keeping for bn_expand. */
    int neg;                    /* one if the number is negative */
    //int flags;

} BIGNUM;

#endif /* __BN_H__ */
