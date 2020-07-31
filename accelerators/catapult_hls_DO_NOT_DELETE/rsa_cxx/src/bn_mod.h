#ifndef __BN_MOD_H__
#define __BN_MOD_H__

#include "bn_div.h"

int BN_nnmod(BIGNUM *r,
             BIGNUM *m,
             BIGNUM *d)
{
    if (!(BN_mod(r, m, d)))
        return 0;

    if (!r->neg)
        return 1;

    if (d->neg)
        return BN_sub(r, r, d);

    return BN_add(r, r, d);
}

BIGNUM *int_bn_mod_inverse(BIGNUM *in,
                           BIGNUM *a,
                           BIGNUM *n)
{
    int sign;
    BIGNUM A, B, X, Y, M, D, T;

    BN_one(&X);
    BN_zero(&Y);
    BN_copy(&B, a);
    BN_copy(&A, n);
    A.neg = 0;

    if (B.neg || (BN_ucmp(&B, &A) >= 0))
    {
        if (!BN_nnmod(&B, &B, &A))
            goto err;
    }

    sign = -1;

    /* general inversion algorithm */

    while (!BN_is_zero(&B))
    {
        BIGNUM tmp;

        /*-
         *      0 < B < A,
         * (*) -sign*X*a  ==  B   (mod |n|),
         *      sign*Y*a  ==  A   (mod |n|)
         */

        /* (D, M) := (A/B, A%B) ... */
        if (BN_num_bits(&A) == BN_num_bits(&B))
        {
            if (!BN_one(&D))
                goto err;

            if (!BN_sub(&M, &A, &B))
                goto err;

        }
        else if (BN_num_bits(&A) == BN_num_bits(&B) + 1)
        {
            /* A/B is 1, 2, or 3 */
            if (!BN_lshift(&T, &B, 1))
                goto err;

            if (BN_ucmp(&A, &T) < 0)
            {
                /* A < 2*B, so D=1 */
                if (!BN_one(&D))
                    goto err;
                if (!BN_sub(&M, &A, &B))
                    goto err;
            }
            else
            {
                /* A >= 2*B, so D=2 or D=3 */
                if (!BN_sub(&M, &A, &T))
                    goto err;

                if (!BN_add(&D, &T, &B))
                    goto err; /* use D (:= 3*B) as temp */

                if (BN_ucmp(&A, &D) < 0)
                {
                    /* A < 3*B, so D=2 */
                    if (!BN_set_word(&D, 2))
                        goto err;
                    /*
                     * M (= A - 2*B) already has the correct value
                     */
                }
                else
                {
                    /* only D=3 remains */
                    if (!BN_set_word(&D, 3))
                        goto err;
                    /*
                     * currently M = A - 2*B, but we need M = A - 3*B
                     */
                    if (!BN_sub(&M, &M, &B))
                        goto err;
                }
            }
        }
        else
        {
            BN_zero(&D);
            if (!BN_div(&D, &M, &A, &B))
                goto err;
        }

        /*-
         * Now
         *      A = D*B + M;
         * thus we have
         * (**)  sign*Y*a  ==  D*B + M   (mod |n|).
         */

        BN_copy(&tmp, &A);

        /* (A, B) := (B, A mod B) ... */
        BN_copy(&A, &B);
        BN_copy(&B, &M);

        /* ... so we have  0 <= B < A  again */

        /*-
         * Since the former  M  is now  B  and the former  B  is now  A,
         * (**) translates into
         *       sign*Y*a  ==  D*A + B    (mod |n|),
         * i.e.
         *       sign*Y*a - D*A  ==  B    (mod |n|).
         * Similarly, (*) translates into
         *      -sign*X*a  ==  A          (mod |n|).
         *
         * Thus,
         *   sign*Y*a + D*sign*X*a  ==  B  (mod |n|),
         * i.e.
         *        sign*(Y + D*X)*a  ==  B  (mod |n|).
         *
         * So if we set  (X, Y, sign) := (Y + D*X, X, -sign), we arrive back at
         *      -sign*X*a  ==  B   (mod |n|),
         *       sign*Y*a  ==  A   (mod |n|).
         * Note that  X  and  Y  stay non-negative all the time.
         */

        /*
         * most of the time D is very small, so we can optimize tmp := D*X+Y
         */
        if (BN_is_one(&D))
        {
            if (!BN_add(&tmp, &X, &Y))
                goto err;
        }
        else
        {
            if (BN_is_word(&D, 2))
            {
                if (!BN_lshift(&tmp, &X, 1))
                    goto err;
            }
            else if (BN_is_word(&D, 4))
            {
                if (!BN_lshift(&tmp, &X, 2))
                    goto err;
            }
            else if (D.top == 1)
            {
                if (!BN_copy(&tmp, &X))
                    goto err;
                if (!BN_mul_word(&tmp, D.d[0]))
                    goto err;
            }
            else
            {
                if (!BN_mul(&tmp, &D, &X))
                    goto err;
            }

            if (!BN_add(&tmp, &tmp, &Y))
                goto err;
        }

        BN_copy(&M, &Y);
        BN_copy(&Y, &X);
        BN_copy(&X, &tmp);
        sign = -sign;
    }

    /*-
     * The while loop (Euclid's algorithm) ends when
     *      A == gcd(a,n);
     * we have
     *       sign*Y*a  ==  A  (mod |n|),
     * where  Y  is non-negative.
     */

    if (sign < 0)
    {
        if (!BN_sub(&Y, n, &Y))
            goto err;
    }
    /* Now  Y*a  ==  A  (mod |n|).  */

    if (BN_is_one(&A))
    {
        /* Y*a == 1  (mod |n|) */
        if (!Y.neg && BN_ucmp(&Y, n) < 0)
        {
            if (!BN_copy(in, &Y))
                goto err;
        }
        else
        {
            if (!BN_nnmod(in, &Y, n))
                goto err;
        }
    }
    else
    {
        goto err;
    }

err:
    return in;
}

BIGNUM *BN_mod_inverse(BIGNUM *in,
                       BIGNUM *a,
                       BIGNUM *n)
{
    return int_bn_mod_inverse(in, a, n);
}

#endif /* __BN_MOD_H__ */
