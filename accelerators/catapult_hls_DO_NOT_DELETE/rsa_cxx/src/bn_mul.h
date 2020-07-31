#ifndef __BN_MUL_H__
#define __BN_MUL_H__

#include "bn_common.h"

#define LBITS(a)        ((a) & BN_MASK2l)
#define LLBITS(a)       ((a) & BN_MASKl)

#define HBITS(a)        (((a) >> BN_BITS4) & BN_MASK2l)
#define LHBITS(a)       (((a) >> BN_BITS2) & BN_MASKl)

#define L2HBITS(a)      (((a) << BN_BITS4) & BN_MASK2)
#define LL2HBITS(a)     ((BN_ULLONG)((a) & BN_MASKl) << BN_BITS2)

#define mul64(l, h, bl, bh)                     \
    {                                           \
        BN_ULONG m, m1, lt, ht;                 \
        lt = l;                                 \
        ht = h;                                 \
        m  = (bh) * (lt);                       \
        lt = (bl) * (lt);                       \
        m1 = (bl) * (ht);                       \
        ht = (bh) * (ht);                       \
        m = (m + m1) & BN_MASK2;                \
        if (m < m1) ht += L2HBITS((BN_ULONG)1); \
        ht += HBITS(m);                         \
        m1 = L2HBITS(m);                        \
        lt = (lt + m1) & BN_MASK2;              \
        if (lt < m1) ht++;                      \
        (l) = lt;                               \
        (h) = ht;                               \
    }

#define mul_add(r, a, bl, bh, c)                \
    {                                           \
        BN_ULONG l, h;                          \
        l = LBITS(a);                           \
        h = HBITS(a);                           \
        mul64(l, h, (bl), (bh));                \
        l = (l + (c)) & BN_MASK2;               \
        if (l < (c)) h++;                       \
        (c) = (r);                              \
        l = (l + (c))&BN_MASK2;                 \
        if (l < (c)) h++;                       \
        (c) = h & BN_MASK2;                     \
        (r) = l;                                \
    }

#define mul(r, a, bl, bh, c)                    \
    {                                           \
        BN_ULONG l, h;                          \
        l = LBITS(a);                           \
        h = HBITS(a);                           \
        mul64(l, h, (bl), (bh));                \
        l = l + (c);                            \
        if ((l & BN_MASK2) < (c)) h++;          \
        (c)= h & BN_MASK2;                      \
        (r)= l & BN_MASK2;                      \
    }

BN_ULONG bn_mul_add_words(BN_ULONG rp[MAX_BN_SIZE],
                          BN_ULONG ap[MAX_BN_SIZE],
                          int num,
                          BN_ULONG w)
{
    BN_ULONG bl, bh;
    BN_ULONG carry = 0;

    if (num <= 0)
        return (BN_ULONG) 0;

    bl = LBITS(w);
    bh = HBITS(w);

    for (int i = 0; i < num; ++i)
        mul_add(rp[i], ap[i], bl, bh, carry);

    return carry;
}

BN_ULONG bn_mul_words(BN_ULONG rp[MAX_BN_SIZE],
                      BN_ULONG ap[MAX_BN_SIZE],
                      int num,
                      BN_ULONG w)
{
    BN_ULONG bl, bh;
    BN_ULONG carry = 0;

    if (num <= 0)
        return (BN_ULONG) 0;

    bl = LBITS(w);
    bh = HBITS(w);

    for (int i = 0; i < num; ++i)
        mul(rp[i], ap[i], bl, bh, carry);

    return carry;
}

int BN_mul_word(BIGNUM *a,
                BN_ULONG w)
{
    BN_ULONG ll;

    w &= BN_MASK2;

    if (a->top)
    {
        if (w == 0)
            BN_zero(a);
        else
        {
            ll = bn_mul_words(a->d, a->d, a->top, w);

            if (ll)
            {
                a->d[a->top++] = ll;
            }
        }
    }

    return 1;
}

void bn_mul_normal(BN_ULONG r[MAX_BN_SIZE],
                   BN_ULONG a[MAX_BN_SIZE], int na,
                   BN_ULONG b[MAX_BN_SIZE], int nb)
{
    BN_ULONG *rr;

    if (nb <= na)
    {
        rr = &(r[na]);

        if (nb <= 0)
        {
            (void) bn_mul_words(r, a, na, 0);
            return;
        }
        else
        {
            rr[0] = bn_mul_words(r, a, na, b[0]);
        }

        for (int i = 1; i < nb; ++i)
        {
            rr[i] = bn_mul_add_words(&(r[i]), a, na, b[i]);
        }
    }
    else
    {
        rr = &(r[nb]);

        if (na <= 0)
        {
            (void) bn_mul_words(r, b, nb, 0);
            return;
        }
        else
        {
            rr[0] = bn_mul_words(r, b, nb, a[0]);
        }

        for (int i = 1; i < na; ++i)
        {
            rr[i] = bn_mul_add_words(&(r[i]), b, nb, a[i]);
        }
    }
}

int bn_mul_fixed_top(BIGNUM *r,
                     BIGNUM *a,
                     BIGNUM *b)
{
    if ((a->top == 0) || (b->top == 0))
    {
        BN_zero(r);
        return 1;
    }

    r->top = a->top + b->top;
    r->neg = a->neg ^ b->neg;

    bn_mul_normal(r->d, a->d, a->top,
                        b->d, b->top);

    return 1;
}

int BN_mul(BIGNUM *r,
           BIGNUM *a,
           BIGNUM *b)
{
    int ret = bn_mul_fixed_top(r, a, b);

    bn_correct_top(r);
    return ret;
}

#endif /* __BN_MUL_H__ */
