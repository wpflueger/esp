#ifndef __GCM_H__
#define __GCM_H__

#include "string_mntr.h"

#include "../defines.h"
#include "../exp.h"
#include "../enc.h"
#include "../dec.h"

/* Galois/Counter Mode */

static void inc_block(uint8_t *b)
{
    /* Increment by 1 a block */

    uint32_t val;
    GET32(val, (b + BLOCK_BYTES - 4));
    PUT32(b + BLOCK_BYTES - 4, val + 1);
}

static void rsh_block(uint8_t *v)
{
    /* Right shift of a block */

    uint32_t val;

    GET32(val, v + 12);
    val >>= 1;
    if (v[11] & 0x01)
        val |= 0x80000000;
    PUT32(v + 12, val);

    GET32(val, v + 8);
    val >>= 1;
    if (v[7] & 0x01)
        val |= 0x80000000;
    PUT32(v + 8, val);

    GET32(val, v + 4);
    val >>= 1;
    if (v[3] & 0x01)
        val |= 0x80000000;
    PUT32(v + 4, val);

    GET32(val, v + 0);
    val >>= 1;
    PUT32(v + 0, val);
}

static void gf_mult(uint8_t *x,
                    uint8_t *y,
                    uint8_t *z)
{
    /* Multiplication in GF(2^128) */

    int i, j, k;
    uint8_t v[16];

    /* Z_0 = 0^128 */
    for (k = 0; k < 16; ++k)
        z[k] = 0;

    /* V_0 = 0^128 */
    for (k = 0; k < 16; ++k)
        v[k] = y[k];

    for (i = 0; i < 16; i++)
    {
        for (j = 0; j < 8; j++)
        {
            if (x[i] & BIT(7 - j))
            {
                /* Z_(i + 1) = Z_i XOR V_i */
                for (k = 0; k < 16; ++k)
                    z[k] ^= v[k];
            }

            if (v[15] & 0x01)
            {
                /* V_(i + 1) = V_i >> 1 */
                rsh_block(v);

                /* V_(i + 1) ^= R */
                v[0] ^= 0xe1;
            }
            else
            {
                /* V_(i + 1) = V_i >> 1 */
                rsh_block(v);
            }
        }
    }
}

static void ghash(uint32_t x_len,
                  uint8_t *h,
                  uint8_t *x,
                  uint8_t *y)
{
    /* NIST Special Publication 800-38D (pag 12) */

    uint8_t tmp[16];
    unsigned i, j, k;

    for (i = 0, j = 0; i < (x_len >> 4); i++, j += 16)
    {
        #pragma HLS loop_tripcount min=1 max=16

        /* printf("enter for\n"); */
        /* Y_i = (Y_(i-1) XOR X_i) dot H */
        for (k = 0; k < 16; ++k)
            y[k] ^= x[j + k];

        /* dot operation */
        gf_mult(y, h, tmp);

        for (k = 0; k < 16; ++k)
            y[k] = tmp[k];

        /*always correct*/
        /* printf("h:"); */
        /* for (int k = 0; k < 16; ++k) */
            /* printf("%02x", h[k]); */
        /* printf("\n"); */

        /* printf("x:"); */
        /* for (int k = 0; k < 16; ++k) */
            /* printf("%02x", x[j + k]); */
        /* printf("\n"); */

        /* printf("y:"); */
        /* for (int k = 0; k < 16; ++k) */
            /* printf("%02x", y[k]); */
        /* printf("\n"); */
    }

    if (x_len > j)
    {
        /* printf("enter if\n"); */
        /* Add zero padded last block */
        memset_mntr<uint8_t>(tmp, 0, sizeof(tmp));

        for (k = 0; k < x_len - j; ++k)
            tmp[k] = x[k + j];

        /* Y_i = (Y^(i-1) XOR X_i) dot H */
        for (k = 0; k < 16; ++k)
            y[k] ^= tmp[k];

        /* dot operation */
        gf_mult(y, h, tmp);

        for (k = 0; k < 16; ++k)
            y[k] = tmp[k];
    }
}

static void gcm_gctr(uint32_t key_bytes,
                     uint32_t input_bytes,
                     uint8_t in[MAX_IN_BYTES],
                     uint8_t out[MAX_IN_BYTES],
                     uint32_t ekey[EXP_KEY_SIZE],
                     uint8_t J0[BLOCK_BYTES],
                     uint32_t *total_blocks)
{
    /* NIST Special Publication 800-38D (pag 13) */

    unsigned i, j;
    uint8_t cb[BLOCK_BYTES];
    uint8_t tmp[BLOCK_BYTES];

    for (i = 0; i < BLOCK_BYTES; ++i)
        cb[i] = J0[i];

    for (i = 0; i < *total_blocks; ++i)
    {
        #pragma HLS loop_tripcount min=1 max=1
        inc_block(cb);
    }

    for (i = 0; i < input_bytes; i += BLOCK_BYTES)
    {
        #pragma HLS loop_tripcount min=1 max=16

        inc_block(cb);

        /* Use the underlying block cipher */
        aes_encrypt(key_bytes, cb, tmp, ekey);

        /* (i + j < input_bytes) is for the last block */
        for (j = 0; j < 16 && i + j < input_bytes; ++j)
        {
            #pragma HLS loop_tripcount min=16 max=16
            out[i + j] = tmp[j] ^ in[i + j];
        }

        *total_blocks += 1;
    }
}

static void gcm_compute_j0(uint32_t iv_bytes,
                           uint8_t *iv,
                           uint8_t *H,
                           uint8_t *J0)
{
    /* NIST Special Publication 800-38D (pag 15) */
    /* In the following || is the concatenation. */
    /* This code assumes J0 is initialized with 0. */

    unsigned k;
    uint8_t len_buf[16] = { 0x00 };

    if (iv_bytes == 12)
    {
        /* J_0 = IV || 0^31 || 1 */
        for (k = 0; k < iv_bytes; ++k)
        {
            #pragma HLS loop_tripcount min=12 max=12

            J0[k] = iv[k];
        }

        J0[BLOCK_BYTES - 1] = 0x01;
    }
    else
    {
        /* s =  128 * (iv_bytes / 128) - iv_bytes */
        /* J_0 = GHASH(IV || 0^(s + 64) || (iv_bytes)_64) */
        ghash(iv_bytes, H, iv, J0);
        PUT64(len_buf + 8, iv_bytes << 3);
        ghash(16, H, len_buf, J0);
    }
}

#include <stdlib.h>

int aes_gcm_cipher(uint32_t encryption,
                   uint32_t key_bytes,
                   uint32_t input_bytes,
                   uint32_t iv_bytes,
                   uint32_t aad_bytes,
                   uint32_t tag_bytes,
                   uint32_t ekey[EXP_KEY_SIZE],
                   uint8_t iv[MAX_IV_BYTES],
                   uint8_t in[MAX_IN_BYTES],
                   uint8_t out[MAX_IN_BYTES],
                   uint8_t aad[MAX_IN_BYTES],
                   uint8_t tag[MAX_IN_BYTES])
{
    unsigned k;
    int check = 0;
    static uint8_t S[BLOCK_BYTES]       = { 0 };
    static uint8_t T[BLOCK_BYTES]       = { 0 };
    static uint8_t H[BLOCK_BYTES]       = { 0 };
    static uint8_t J0[BLOCK_BYTES]      = { 0 };
    static uint8_t len_buf[BLOCK_BYTES] = { 0 };

    static bool init_done = false;
    static uint32_t total_bytes = 0;
    static uint32_t total_blocks = 0;

    if (!init_done)
    {
        init_done = true;

        /* Generate hash H = AES_K(0^128) */
        aes_encrypt(key_bytes, H, H, ekey);

        /* Compute the pre-counter block J0 */
        gcm_compute_j0(iv_bytes, iv, H, J0);

        ghash(aad_bytes, H, aad, S);
        PUT64(len_buf, aad_bytes << 3);
    }

    if (tag_bytes == 0)
    {
        if (input_bytes != 0)
             gcm_gctr(key_bytes, input_bytes, in, out, ekey, J0, &total_blocks);

        if (encryption == ENCRYPTION_MODE)
            ghash(input_bytes, H, out, S);
        else if (encryption == DECRYPTION_MODE)
            ghash(input_bytes, H, in, S);

        total_bytes += input_bytes;
    }

    if (tag_bytes != 0)
    {
        init_done = false;

        PUT64(len_buf + 8, total_bytes << 3);
        ghash(sizeof(len_buf), H, len_buf, S);

        aes_encrypt(key_bytes, J0, T, ekey);

        for (k = 0; k < 16; ++k)
            T[k] = T[k] ^ S[k];

        if (encryption == DECRYPTION_MODE)
        {
            for (k = 0; k < tag_bytes; ++k)
            {
                #pragma HLS loop_tripcount min=16 max=16

                if (tag[k] != T[k])
                    check = -1;
            }
        }
        else if (encryption == ENCRYPTION_MODE)
        {
            for (k = 0; k < tag_bytes; ++k)
            {
                #pragma HLS loop_tripcount min=16 max=16

                tag[k] = T[k];
            }
        }

        total_bytes = 0;
        total_blocks = 0;

        memset_mntr<uint8_t>(S,       0, 16           * sizeof(uint8_t));
        memset_mntr<uint8_t>(T,       0, 16           * sizeof(uint8_t));
        memset_mntr<uint8_t>(H,       0, BLOCK_BYTES  * sizeof(uint8_t));
        memset_mntr<uint8_t>(J0,      0, BLOCK_BYTES  * sizeof(uint8_t));
        memset_mntr<uint8_t>(len_buf, 0, 16           * sizeof(uint8_t));
    }

    return check;
}

#endif /* __GCM_H__ */
