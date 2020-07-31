#ifndef __BN_COMMON_H__
#define __BN_COMMON_H__

void bn_correct_top(BIGNUM *a)
{
    int i;
    int tmp_top = a->top;

    if (tmp_top > 0)
    {
        for (i = tmp_top - 1; tmp_top > 0; i--, tmp_top--)
            if (a->d[i] != 0) break;
        a->top = tmp_top;
    }

    if (a->top == 0)
        a->neg = 0;
}

int BN_is_odd(BIGNUM *a)
{
    return (a->top > 0) && (a->d[0] & 1);
}

int BN_abs_is_word(BIGNUM *a, BN_ULONG w)
{
    return ((a->top == 1) && (a->d[0] == w)) ||
        ((w == 0) && (a->top == 0));
}

int BN_is_word(BIGNUM *a, BN_ULONG w)
{
    return BN_abs_is_word(a, w) && (!w || !a->neg);
}

int BN_is_one(BIGNUM *a)
{
    return BN_abs_is_word(a, 1) && !a->neg;
}

int BN_is_zero(BIGNUM *a)
{
    return a->top == 0;
}

int BN_is_negative(BIGNUM *a)
{
    return (a->neg != 0);
}

int BN_is_bit_set(BIGNUM *a, int n)
{
    int i, j;

    if (n < 0)
        return 0;
    i = n >> BN_BITS2_LG;
    j = n & BN_BITS2_MOD;
    if (a->top <= i)
        return 0;
    return (int)(((a->d[i]) >> j) & ((BN_ULONG)1));
}

BIGNUM *BN_value_one(void)
{
    static BN_ULONG data_one = 1L;
    static BIGNUM const_one;

    const_one.d[0] = data_one;
    const_one.top  = 1;
    //const_one.dmax = 1;
    const_one.neg = 0;

    return &const_one;
}

void BN_set_negative(BIGNUM *a, int b)
{
    if (b && !BN_is_zero(a))
        a->neg = 1;
    else
        a->neg = 0;
}

int BN_set_word(BIGNUM *a, BN_ULONG w)
{
    //if (bn_expand(a, (int)sizeof(BN_ULONG) * 8) == NULL)
    //    return 0;
    a->neg = 0;
    a->d[0] = w;
    a->top = (w ? 1 : 0);
    //a->dmax = 1000;
    return 1;
}


int BN_ucmp(BIGNUM *a, BIGNUM *b)
{
    int i;
    BN_ULONG t1, t2, *ap, *bp;

    i = a->top - b->top;
    if (i != 0)
        return i;
    ap = a->d;
    bp = b->d;
    for (i = a->top - 1; i >= 0; i--)
    {
        t1 = ap[i];
        t2 = bp[i];
        if (t1 != t2)
            return ((t1 > t2) ? 1 : -1);
    }
    return 0;
}

#define BN_zero(a)      (BN_set_word((a),0))
#define BN_one(a)       (BN_set_word((a),1))



int BN_num_bits_word(BN_ULONG l)
{
    BN_ULONG x, mask;
    int bits = (l != 0);

#if BN_BITS2 > 32
    x = l >> 32;
    mask = (0 - x) & BN_MASK2;
    mask = (0 - (mask >> (BN_BITS2 - 1)));
    bits += 32 & mask;
    l ^= (x ^ l) & mask;
#endif

    x = l >> 16;
    mask = (0 - x) & BN_MASK2;
    mask = (0 - (mask >> (BN_BITS2 - 1)));
    bits += 16 & mask;
    l ^= (x ^ l) & mask;

    x = l >> 8;
    mask = (0 - x) & BN_MASK2;
    mask = (0 - (mask >> (BN_BITS2 - 1)));
    bits += 8 & mask;
    l ^= (x ^ l) & mask;

    x = l >> 4;
    mask = (0 - x) & BN_MASK2;
    mask = (0 - (mask >> (BN_BITS2 - 1)));
    bits += 4 & mask;
    l ^= (x ^ l) & mask;

    x = l >> 2;
    mask = (0 - x) & BN_MASK2;
    mask = (0 - (mask >> (BN_BITS2 - 1)));
    bits += 2 & mask;
    l ^= (x ^ l) & mask;

    x = l >> 1;
    mask = (0 - x) & BN_MASK2;
    mask = (0 - (mask >> (BN_BITS2 - 1)));
    bits += 1 & mask;

    return bits;
}

#define BN_num_bytes(a) ((BN_num_bits(a)+7)/8)

BIGNUM *BN_copy(BIGNUM *a, BIGNUM *b)
{
    int k = 0;

    for (k = 0; k < b->top; ++k)
        a->d[k] = b->d[k];
    a->neg = b->neg;
    a->top = b->top;

    return a;
}

int BN_num_bits(BIGNUM *a)
{
    int i = a->top - 1;
    if (BN_is_zero(a))
        return 0;
    return ((i << BN_BITS2_LG) + BN_num_bits_word(a->d[i]));
}

int BN_mask_bits(BIGNUM *a, int n)
{
    int b, w;

    if (n < 0)
        return 0;

    w = n >> BN_BITS2_LG;
    b = n & BN_BITS2_MOD;
    if (w >= a->top)
        return 0;
    if (b == 0)
        a->top = w;
    else {
        a->top = w + 1;
        a->d[w] &= ~(BN_MASK2 << b);
    }
    bn_correct_top(a);
    return 1;
}

int BN_set_bit(BIGNUM *a, int n)
{
    int i, j, k;

    if (n < 0)
        return 0;

    i = n >> BN_BITS2_LG;
    j = n & BN_BITS2_MOD;
    if (a->top <= i) {
        //if (bn_wexpand(a, i + 1) == NULL)
        //    return 0;
        for (k = a->top; k < i + 1; k++)
            a->d[k] = 0;
        a->top = i + 1;
    }

    a->d[i] |= (((BN_ULONG)1) << j);
    return 1;
}

int BN_bn2binpad(BIGNUM *a, uint8_t out[RSA_MAX_BLOCK_SIZE], uint32_t out_len)
{
    uint32_t i, lasti, j, atop, mask, k = 0;
    BN_ULONG l;

    atop = a->top << BN_BYTES_LG;
    lasti = (MAX_BN_SIZE << BN_BYTES_LG) - 1;

    for (i = 0, j = 0, k += out_len; j < out_len; j++)
    {
        l = a->d[i >> BN_BYTES_LG];
        mask = 0 - ((j - atop) >> (8 * sizeof(i) - 1));
        out[--k] = (uint8_t)(l >> (8 * (i & BN_BYTES_MOD)) & mask);
        i += (i - lasti) >> (8 * sizeof(i) - 1); /* stay on last limb */
    }

    return out_len;
}

void BN_bin2bn(uint8_t in[RSA_MAX_BLOCK_SIZE], uint32_t in_len, BIGNUM *ret)
{
    BN_ULONG l;
    unsigned int j;
    unsigned int i;
    unsigned int m;

    m = ((in_len - 1) & BN_BYTES_MOD);
    i = ((in_len - 1) >> BN_BYTES_LG) + 1;

    ret->top = i;
    ret->neg = 0;
    l = 0;

    for (j = 0; j < in_len; ++j)
    {
        l = (l << 8L) | (in[j]);

        if (m-- == 0)
        {
            ret->d[--i] = l;
            l = 0;
            m = BN_BYTES - 1;
        }
    }

    bn_correct_top(ret);
}

#endif /* __BN_COMMON_H__ */
