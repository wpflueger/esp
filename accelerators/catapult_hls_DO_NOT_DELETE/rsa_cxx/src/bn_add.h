#ifndef __BN_ADD_H__
#define __BN_ADD_H__

#include "bn_common.h"

int BN_sub_word_1(BIGNUM *a)
{
    int i;
    BN_ULONG w = 1;

    if (BN_is_zero(a))
    {
        i = BN_set_word(a, w);
        if (i != 0)
            BN_set_negative(a, 1);
        return i;
    }

    if ((a->top == 1) && (a->d[0] < w))
    {
        a->d[0] = w - a->d[0];
        a->neg = 1;
        return 1;
    }

    i = 0;
    for (;;)
    {
        if (a->d[i] >= w)
        {
            a->d[i] -= w;
            break;
        }
        else
        {
            a->d[i] = (a->d[i] - w) & BN_MASK2;
            i++;
            w = 1;
        }
    }

    if ((a->d[i] == 0) && (i == (a->top - 1)))
        a->top--;

    return 1;
}

BN_ULONG bn_sub_words(BN_ULONG r[MAX_BN_SIZE],
                      BN_ULONG a[MAX_BN_SIZE],
                      BN_ULONG b[MAX_BN_SIZE],
                      int n)
{
    int c = 0;
    BN_ULONG t1, t2;
    unsigned r_index = 0;
    unsigned a_index = 0;
    unsigned b_index = 0;

    if (n <= 0)
        return (BN_ULONG) 0;

    while (n)
    {
        t1 = a[a_index];
        t2 = b[b_index];
        r[r_index] = (t1 - t2 - c) & BN_MASK2;
        if (t1 != t2)
            c = (t1 < t2);
        a_index++;
        b_index++;
        r_index++;
        n--;
    }

    return c;
}

BN_ULONG bn_add_words(BN_ULONG r[MAX_BN_SIZE],
                      BN_ULONG a[MAX_BN_SIZE],
                      BN_ULONG b[MAX_BN_SIZE],
                      int n)
{
    BN_ULONG c, l, t;
    unsigned r_index = 0;
    unsigned a_index = 0;
    unsigned b_index = 0;

    if (n <= 0)
        return (BN_ULONG) 0;

    c = 0;

    while (n)
    {
        t = a[a_index];
        t = (t + c) & BN_MASK2;
        c = (t < c);
        l = (t + b[b_index]) & BN_MASK2;
        c += (l < t);
        r[r_index] = l;
        a_index++;
        b_index++;
        r_index++;
        n--;
    }

    return (BN_ULONG) c;
}

int BN_usub(BIGNUM *r,
            BIGNUM *a,
            BIGNUM *b)
{
    int max, min, dif;
    BN_ULONG t1, t2, borrow, *rp;
    BN_ULONG *ap, *bp;

    max = a->top;
    min = b->top;
    dif = max - min;

    if (dif < 0)
    {
        /* hmm... should not be happening */
        return 0;
    }

    ap = a->d;
    bp = b->d;
    rp = r->d;

    borrow = bn_sub_words(rp, ap, bp, min);
    ap += min;
    rp += min;

    while (dif)
    {
        dif--;
        t1 = *(ap++);
        t2 = (t1 - borrow) & BN_MASK2;
        *(rp++) = t2;
        borrow &= (t1 == 0);
    }

    while (max && *--rp == 0)
        max--;

    r->top = max;
    r->neg = 0;

    return 1;
}

int BN_uadd(BIGNUM *r,
            BIGNUM *a,
            BIGNUM *b)
{
    int max, min, dif;
    BN_ULONG *ap, *bp;
    BN_ULONG *rp, carry, t1, t2;

    if (a->top < b->top)
    {
        BIGNUM *tmp;
        tmp = a;
        a = b;
        b = tmp;
    }

    max = a->top;
    min = b->top;
    dif = max - min;

    r->top = max;

    ap = a->d;
    bp = b->d;
    rp = r->d;

    carry = bn_add_words(rp, ap, bp, min);
    rp += min;
    ap += min;

    while (dif)
    {
        dif--;
        t1 = *(ap++);
        t2 = (t1 + carry) & BN_MASK2;
        *(rp++) = t2;
        carry &= (t2 == 0);
    }

    *rp = carry;
    r->top += carry;
    r->neg = 0;

    return 1;
}

/* Forward declaration. */

int BN_add(BIGNUM *r,
           BIGNUM *a,
           BIGNUM *b);


int BN_sub(BIGNUM *r,
           BIGNUM *a,
           BIGNUM *b)
{
    int ret, r_neg, cmp_res;

    if (a->neg != b->neg)
    {
        r_neg = a->neg;
        ret = BN_uadd(r, a, b);
    }
    else
    {
        cmp_res = BN_ucmp(a, b);

        if (cmp_res > 0)
        {
            r_neg = a->neg;
            ret = BN_usub(r, a, b);
        }
        else if (cmp_res < 0)
        {
            r_neg = !b->neg;
            ret = BN_usub(r, b, a);
        }
        else
        {
            r_neg = 0;
            BN_zero(r);
            ret = 1;
        }
    }

    r->neg = r_neg;
    return ret;
}

int BN_add(BIGNUM *r,
           BIGNUM *a,
           BIGNUM *b)
{
    int ret, r_neg, cmp_res;

    if (a->neg == b->neg)
    {
        r_neg = a->neg;
        ret = BN_uadd(r, a, b);
    }
    else
    {
        cmp_res = BN_ucmp(a, b);

        if (cmp_res > 0)
        {
            r_neg = a->neg;
            ret = BN_usub(r, a, b);
        }
        else if (cmp_res < 0)
        {
            r_neg = b->neg;
            ret = BN_usub(r, b, a);
        }
        else
        {
            r_neg = 0;
            BN_zero(r);
            ret = 1;
        }
    }

    r->neg = r_neg;
    return ret;
}

#endif /* __BN_ADD_H__ */
