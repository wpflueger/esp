#ifndef __BN_DIV_H__
#define __BN_DIV_H__

#include "bn_common.h"
#include "bn_shift.h"

static int bn_left_align(BIGNUM *num)
{
    BN_ULONG *d = num->d, n, m, rmask;
    int top = num->top;
    int rshift = BN_num_bits_word(d[top - 1]), lshift, i;

    lshift = BN_BITS2 - rshift;
    rshift &= BN_BITS2_MOD;            /* say no to undefined behaviour */
    rmask = (BN_ULONG)0 - rshift;  /* rmask = 0 - (rshift != 0) */
    rmask |= rmask >> 8;

    for (i = 0, m = 0; i < top; i++) {
        n = d[i];
        d[i] = ((n << lshift) | m) & BN_MASK2;
        m = (n >> rshift) & rmask;
    }

    return lshift;
}

# define BN_mod(rem,m,d) { BIGNUM unused; BN_zero(&unused); BN_div(&unused,(rem),(m),(d)); }

BN_ULONG bn_div_words(BN_ULONG h, BN_ULONG l, BN_ULONG d)
{
    BN_ULONG dh, dl, q, ret = 0, th, tl, t;
    int i, count = 2;

    if (d == 0)
        return BN_MASK2;

    i = BN_num_bits_word(d);
    // assert((i == BN_BITS2) || (h <= (BN_ULONG)1 << i));

    i = BN_BITS2 - i;
    if (h >= d)
        h -= d;

    if (i) {
        d <<= i;
        h = (h << i) | (l >> (BN_BITS2 - i));
        l <<= i;
    }
    dh = (d & BN_MASK2h) >> BN_BITS4;
    dl = (d & BN_MASK2l);
    for (;;) {
        if ((h >> BN_BITS4) == dh)
            q = BN_MASK2l;
        else
            q = h / dh;

        th = q * dh;
        tl = dl * q;
        for (;;) {
            t = h - th;
            if ((t & BN_MASK2h) ||
                ((tl) <= ((t << BN_BITS4) | ((l & BN_MASK2h) >> BN_BITS4))))
                break;
            q--;
            th -= dh;
            tl -= dl;
        }
        t = (tl >> BN_BITS4);
        tl = (tl << BN_BITS4) & BN_MASK2h;
        th += t;

        if (l < tl)
            th++;
        l -= tl;
        if (h < th) {
            h += d;
            q--;
        }
        h -= th;

        if (--count == 0)
            break;

        ret = q << BN_BITS4;
        h = ((h << BN_BITS4) | (l >> BN_BITS4)) & BN_MASK2;
        l = (l & BN_MASK2l) << BN_BITS4;
    }
    ret |= q;
    return ret;
}


int bn_div_fixed_top(BIGNUM *dv,
                     BIGNUM *rm,
                     BIGNUM *num,
                     BIGNUM *divisor)
{
    int i, j, loop, norm_shift;

    BIGNUM tmp, snum, sdiv, res;

    int index_wnum;
    int index_wnumtop;

    BN_ULONG d0, d1;
    int num_n, div_n;
    //if (dv != NULL)
    BN_copy(&res, dv);

    BN_copy(&sdiv, divisor);
    norm_shift = bn_left_align(&sdiv);
    sdiv.neg = 0;
    /*
     * Note that bn_lshift_fixed_top's output is always one limb longer
     * than input, even when norm_shift is zero. This means that amount of
     * inner loop iterations is invariant of dividend value, and that one
     * doesn't need to compare dividend and divisor if they were originally
     * of the same bit length.
     */
    if (!(bn_lshift_fixed_top(&snum, num, norm_shift)))
        goto err;

    div_n = sdiv.top;
    num_n = snum.top;

    if (num_n <= div_n)
    {
        for (int i = 0; i < (div_n - num_n + 1); ++i)
            snum.d[num_n + i] = 0;
        snum.top = num_n = div_n + 1;
    }

    loop = num_n - div_n;
    /*
     * Lets setup a 'window' into snum This is the part that corresponds to
     * the current 'area' being divided
     */
    // wnum = &(snum.d[loop]);
    index_wnum = loop;
    // wnumtop = &(snum.d[num_n - 1]);
    index_wnumtop = num_n - 1;

    /* Get the top 2 words of sdiv */
    d0 = sdiv.d[div_n - 1];
    d1 = (div_n == 1) ? 0 : sdiv.d[div_n - 2];

    /* Setup quotient */
    //if (!bn_wexpand(res, loop))
    //    goto err;
    // if (dv != NULL)
    // {
    //     dv->neg = (num->neg ^ divisor->neg);
    //     dv->top = loop;
    // }
    // else
    // {
        res.neg = (num->neg ^ divisor->neg);
        res.top = loop;
    //}

    /* space for temp */
    //if (!bn_wexpand(tmp, (div_n + 1)))
    //    goto err;

    for (i = 0; i < loop; i++, index_wnumtop--)
    {
        BN_ULONG q, l0;
        /*
         * the first part of the loop uses the top two words of snum and sdiv
         * to calculate a BN_ULONG q such that | wnum - sdiv * q | < sdiv
         */
        BN_ULONG n0, n1, rem = 0;

        n0 = snum.d[index_wnumtop];
        n1 = snum.d[index_wnumtop-1];

        if (n0 == d0)
        {
            q = BN_MASK2;
        }
        else /* n0 < d0 */
        {
            BN_ULONG n2 = (index_wnumtop == index_wnum) ? 0 : snum.d[index_wnumtop-2];
            BN_ULONG t2l, t2h;

            q = bn_div_words(n0, n1, d0);
            rem = (n1 - q * d0) & BN_MASK2;

            BN_ULONG ql, qh;
            t2l = LBITS(d1);
            t2h = HBITS(d1);
            ql = LBITS(q);
            qh = HBITS(q);
            mul64(t2l, t2h, ql, qh); /* t2=(BN_ULLONG)d1*q; */

            for (;;)
            {
                if ((t2h < rem) || ((t2h == rem) && (t2l <= n2)))
                    break;
                q--;
                rem += d0;
                if (rem < d0)
                    break;      /* don't let rem overflow */
                if (t2l < d1)
                    t2h--;
                t2l -= d1;
            }
        }

        l0 = bn_mul_words(tmp.d, sdiv.d, div_n, q);
        tmp.d[div_n] = l0;
        index_wnum--;
        /*
         * ignore top values of the bignums just sub the two BN_ULONG arrays
         * with bn_sub_words
         */
        l0 = bn_sub_words(&snum.d[index_wnum], &snum.d[index_wnum], tmp.d, div_n + 1);
        q -= l0;
        /*
         * Note: As we have considered only the leading two BN_ULONGs in
         * the calculation of q, sdiv * q might be greater than wnum (but
         * then (q-1) * sdiv is less or equal than wnum)
         */
        for (l0 = 0 - l0, j = 0; j < div_n; j++)
            tmp.d[j] = sdiv.d[j] & l0;
        l0 = bn_add_words(&snum.d[index_wnum], &snum.d[index_wnum], tmp.d, div_n);
        snum.d[index_wnumtop] += l0;
        // assert((*wnumtop) == 0);

        /* store part of the result */
        // if (dv != NULL)
        // {
        //     dv->d[loop - i - 1] = q;
        // }
        // else
        // {
            res.d[loop - i - 1] = q;
        // }
    }

    snum.top = div_n;
    snum.neg = num->neg;

    // if (rm != NULL)
    bn_rshift_fixed_top(rm, &snum, norm_shift);

    BN_copy(dv, &res);
    return 1;

err:
    return 0;
}


int BN_div(BIGNUM *dv,
           BIGNUM *rm,
           BIGNUM *num,
           BIGNUM *divisor)
{
    int ret;

    ret = bn_div_fixed_top(dv, rm, num, divisor);

    if (ret)
    {
        // if (dv != NULL)
            bn_correct_top(dv);
        // if (rm != NULL)
            bn_correct_top(rm);
    }

    return ret;
}

#endif /* __BN_DIV_H__ */
