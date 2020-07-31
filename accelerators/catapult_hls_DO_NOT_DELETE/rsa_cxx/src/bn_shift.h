#ifndef __BN_SHIFT_H__
#define __BN_SHIFT_H__

#include "bn_common.h"

int bn_lshift_fixed_top(BIGNUM *r,
                        BIGNUM *a,
                        int n)
{
    int i, nw;
    unsigned int lb, rb;
    BN_ULONG *t, *f;
    BN_ULONG l, m, rmask = 0;

    nw = n >> BN_BITS2_LG;

    if (a->top != 0)
    {
        lb = (unsigned int) n & BN_BITS2_MOD;
        rb = BN_BITS2 - lb;
        rb &= BN_BITS2_MOD;
        rmask = (BN_ULONG) 0 - rb;
        rmask |= rmask >> 8;
        f = &(a->d[0]);
        t = &(r->d[nw]);
        l = f[a->top - 1];
        t[a->top] = (l >> rb) & rmask;

        for (i = a->top - 1; i > 0; i--)
        {
            m = l << lb;
            l = f[i - 1];
            t[i] = (m | ((l >> rb) & rmask)) & BN_MASK2;
        }

        t[0] = (l << lb) & BN_MASK2;
    }
    else
    {
        r->d[nw] = 0;
    }

    if (nw != 0)
    {
        for (i = 0; i < nw; ++i)
            r->d[i] = 0;
    }

    r->neg = a->neg;
    r->top = a->top + nw + 1;

    return 1;
}

int BN_lshift(BIGNUM *r,
              BIGNUM *a,
              int n)
{
    int ret;

    if (n < 0)
        return 0;

    ret = bn_lshift_fixed_top(r, a, n);
    bn_correct_top(r);
    return ret;
}

int bn_rshift_fixed_top(BIGNUM *r,
                        BIGNUM *a,
                        int n)
{
    int i, top, nw;
    unsigned int lb, rb;
    BN_ULONG *t, *f;
    BN_ULONG l, m, mask;

    nw = n >> BN_BITS2_LG;
    if (nw >= a->top)
    {
        /* shouldn't happen, but formally required */
        BN_zero(r);
        return 1;
    }

    rb = (unsigned int) n & BN_BITS2_MOD;
    lb = BN_BITS2 - rb;
    lb &= BN_BITS2_MOD;
    mask = (BN_ULONG)0 - lb;
    mask |= mask >> 8;
    top = a->top - nw;

    t = &(r->d[0]);
    f = &(a->d[nw]);
    l = f[0];

    for (i = 0; i < top - 1; i++)
    {
        m = f[i + 1];
        t[i] = (l >> rb) | ((m << lb) & mask);
        l = m;
    }

    t[i] = l >> rb;
    r->neg = a->neg;
    r->top = top;

    return 1;
}

int BN_rshift(BIGNUM *r,
              BIGNUM *a,
              int n)
{
    int i, j, k, p, nw, lb, rb;
    BN_ULONG *t, *f;
    BN_ULONG l, tmp;

    if (n < 0)
        return 0;

    nw = n >> BN_BITS2_LG;
    rb = n & BN_BITS2_MOD;
    lb = BN_BITS2 - rb;

    if (nw >= a->top || a->top == 0)
    {
        BN_zero(r);
        return 1;
    }

    i = (BN_num_bits(a) - n + (BN_BITS2 - 1)) >> BN_BITS2_LG;

    r->neg = a->neg;
    if (n == 0)
           return 1;

    f = &(a->d[nw]);
    t = r->d;
    j = a->top - nw;
    r->top = i;

    if (rb == 0)
    {
        for (i = j, k = 0; i != 0; i--, k++)
            t[k] = f[k];
    }
    else
    {
        k = 0;
        p = 0;
        l = f[k++];

        for (i = j - 1; i != 0; i--)
        {
            tmp = (l >> rb) & BN_MASK2;
            l = f[k++];
            t[p++] = (tmp | (l << lb)) & BN_MASK2;
        }

        if ((l = (l >> rb) & BN_MASK2))
            t[p] = l;
    }

    if (!r->top)
        r->neg = 0;

    return 1;
}

#endif /* __BN_SHIFT_H__ */
