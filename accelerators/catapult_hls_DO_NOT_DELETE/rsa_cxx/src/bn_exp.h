#ifndef __BN_EXP_H__
#define __BN_EXP_H__

#define TABLE_SIZE 32

typedef struct {

    int ri;                     /* number of bits in R */

    BIGNUM RR;                  /* used to convert to montgomery form,
                                   possibly zero-padded */
    BIGNUM N;                   /* The modulus */
    BIGNUM Ni;                  /* R*(1/R mod N) - N*Ni = 1 (Ni is only
                                 * stored for bignum algorithm) */
    BN_ULONG n0[2];             /* least significant word(s) of Ni; (type
                                 * changed with 0.9.9, was "BN_ULONG n0;"
                                 * before) */
} BN_MONT_CTX;


void BN_MONT_CTX_init(BN_MONT_CTX *ctx)
{
    ctx->ri = 0;
    ctx->n0[0] = 0;
    ctx->n0[1] = 0;
    BN_zero(&(ctx->RR));
    BN_zero(&(ctx->N));
    BN_zero(&(ctx->Ni));

}

int BN_MONT_CTX_set(BN_MONT_CTX *mont, BIGNUM *mod)
{
    int i, ret = 0;
    BIGNUM Ri;

    mont->N.neg = 0;

    BN_copy(&(mont->N), mod);
    mont->N.neg = 0;

    mont->ri = BN_num_bits(&mont->N);


    BN_zero(&(mont->RR));
    if (!BN_set_bit(&(mont->RR), mont->ri))
        goto err;           /* R = 2^ri */
    /* Ri = R^-1 mod N */
    BN_zero(&Ri);
    if ((BN_mod_inverse(&Ri, &(mont->RR), &mont->N/*, ctx)*/)) == NULL)
        goto err;
    if (!BN_lshift(&Ri, &Ri, mont->ri))
        goto err;           /* R*Ri */
    if (!BN_sub_word_1(&Ri))
        goto err;
    /*
     * Ni = (R*Ri-1) / N
     */
    BIGNUM notused;
    BN_zero(&notused);
    if (!BN_div(&(mont->Ni), &notused, &Ri, &mont->N))//, ctx))
        goto err;

    /* setup RR for conversions */
    BN_zero(&(mont->RR));
    if (!BN_set_bit(&(mont->RR), mont->ri * 2))
        goto err;
    BN_mod(&(mont->RR), &(mont->RR), &(mont->N));

    for (i = mont->RR.top, ret = mont->N.top; i < ret; i++)
        mont->RR.d[i] = 0;
    mont->RR.top = ret;

    ret = 1;

err:
    return ret;
}

# define BN_window_bits_for_exponent_size(b) \
                ((b) > 671 ? 6 : \
                 (b) > 239 ? 5 : \
                 (b) >  79 ? 4 : \
                 (b) >  23 ? 3 : 1)

int bn_from_mont_fixed_top(BIGNUM *ret,
                           BIGNUM *a,
                           BN_MONT_CTX *mont)
{
    int retn = 0;
    BIGNUM t1, t2;

    BN_zero(&t1);
    BN_zero(&t2);

    if (!BN_copy(&t1, a))
        goto err;
    BN_mask_bits(&t1, mont->ri);

    if (!BN_mul(&t2, &t1, &mont->Ni))
        goto err;
    BN_mask_bits(&t2, mont->ri);

    if (!BN_mul(&t1, &t2, &mont->N))
        goto err;

    if (!BN_add(&t2, a, &t1))
        goto err;

    if (!BN_rshift(ret, &t2, mont->ri))
        goto err;

    if (BN_ucmp(ret, &(mont->N)) >= 0)
        if (!BN_usub(ret, ret, &(mont->N)))
            goto err;

    retn = 1;
 err:
    return retn;
}

int BN_from_montgomery(BIGNUM *ret, BIGNUM *a, BN_MONT_CTX *mont)
{
    int retn;

    retn = bn_from_mont_fixed_top(ret, a, mont);
    bn_correct_top(ret);

    return retn;
}

int bn_mul_mont_fixed_top(BIGNUM *r,
                          BIGNUM *a,
                          BIGNUM *b,
                          BN_MONT_CTX *mont)
{
    BIGNUM tmp;
    int ret = 0;
    int num = mont->N.top;

    if ((a->top + b->top) > 2 * num)
        return 0;

    BN_zero(&tmp);

    if (!bn_mul_fixed_top(&tmp, a, b))
        goto err;

    if (!BN_from_montgomery(r, &tmp, mont))
        goto err;

    ret = 1;

err:
    return ret;
}

int bn_to_mont_fixed_top(BIGNUM *r, BIGNUM *a, BN_MONT_CTX *mont)//,
                         //BN_CTX *ctx)
{
    return bn_mul_mont_fixed_top(r, a, &(mont->RR), mont);//, ctx);
}


int BN_mod_exp_mont(BIGNUM *rr,
                    BIGNUM *a,
                    BIGNUM *p,
                    BIGNUM *m)
{
#pragma HLS INLINE OFF

    int i, j, bits, ret = 0, wstart, wend, window, wvalue;
    int start = 1;
    BIGNUM d, r;
    BIGNUM aa;
    BIGNUM val[TABLE_SIZE];
    BN_MONT_CTX mont;

    BN_zero(&d);
    BN_zero(&r);
    BN_zero(&aa);

    bits = BN_num_bits(p);

    if (bits == 0)
    {
        /* x**0 mod 1, or x**0 mod-1 is still zero. */
        if (BN_abs_is_word(m, 1))
        {
            ret = 1;
            BN_zero(rr);
        }
        else
        {
            ret = BN_one(rr);
        }
        return ret;
    }

    BN_MONT_CTX_init(&mont);
    BN_MONT_CTX_set(&mont, m);

    if (a->neg || BN_ucmp(a, m) >= 0)
    {
        if (!BN_nnmod(&(val[0]), a, m))
            goto err;
        BN_copy(&aa, &(val[0]));
    }
    else
    {
        BN_copy(&aa, a);
    }

    if (!bn_to_mont_fixed_top(&(val[0]), &aa, &mont))//, ctx))
        goto err;               /* 1 */

    window = BN_window_bits_for_exponent_size(bits);

    if (window > 1)
    {
        if (!bn_mul_mont_fixed_top(&d, &(val[0]), &(val[0]), &mont))
            goto err;
        j = 1 << (window - 1);
        for (i = 1; i < j; i++)
        {
            if (!bn_mul_mont_fixed_top(&(val[i]), &(val[i - 1]), &d, &mont))
                goto err;
        }
    }

    start = 1;                  /* This is used to avoid multiplication etc
                                 * when there is only the value '1' in the
                                 * buffer. */
    wvalue = 0;                 /* The 'value' of the window */
    wstart = bits - 1;          /* The top bit of the window */
    wend = 0;                   /* The bottom bit of the window */

                           /* by Shay Gueron's suggestion */
    j = m->top;                 /* borrow j */
    if (m->d[j - 1] & (((BN_ULONG)1) << (BN_BITS2 - 1)))
    {
        r.d[0] = (0 - m->d[0]) & BN_MASK2;
        for (i = 1; i < j; i++)
            r.d[i] = (~m->d[i]) & BN_MASK2;
        r.top = j;
    }
    else
    if (!bn_to_mont_fixed_top(&r, BN_value_one(), &mont))//, ctx))
        goto err;

    for (;;)
    {
        if (BN_is_bit_set(p, wstart) == 0) {
            if (!start) {
                if (!bn_mul_mont_fixed_top(&r, &r, &r, &mont))//ctx))
                    goto err;
            }
            if (wstart == 0)
                break;
            wstart--;
            continue;
        }
        /*
         * We now have wstart on a 'set' bit, we now need to work out how bit
         * a window to do.  To do this we need to scan forward until the last
         * set bit before the end of the window
         */
        j = wstart;
        wvalue = 1;
        wend = 0;
        for (i = 1; i < window; i++) {
            if (wstart - i < 0)
                break;
            if (BN_is_bit_set(p, wstart - i)) {
                wvalue <<= (i - wend);
                wvalue |= 1;
                wend = i;
            }
        }

        /* wend is the size of the current window */
        j = wend + 1;
        /* add the 'bytes above' */
        if (!start)
            for (i = 0; i < j; i++) {
                if (!bn_mul_mont_fixed_top(&r, &r, &r, &mont))//, ctx))
                    goto err;
            }

        /* wvalue will be an odd number < 2^window */
        if (!bn_mul_mont_fixed_top(&r, &r, &(val[wvalue >> 1]), &mont))//, ctx))
            goto err;

        /* move the 'window' down further */
        wstart -= wend + 1;
        wvalue = 0;
        start = 0;
        if (wstart < 0)
            break;
    }

    /*
     * Done with zero-padded intermediate BIGNUMs. Final BN_from_montgomery
     * removes padding [if any] and makes return value suitable for public
     * API consumer.
     */
    if (!BN_from_montgomery(rr, &r, &mont))//, ctx))
        goto err;
    ret = 1;

err:
    return ret;
}

#endif /* __BN_EXP_H__ */
