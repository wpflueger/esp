#ifndef __CBC_H__
#define __CBC_H__

#include "string_mntr.h"

#include "../defines.h"
#include "../exp.h"
#include "../enc.h"
#include "../dec.h"

/* Cipher Block Chaining (CBC) */

int aes_cbc_cipher(uint32_t encryption,
                   uint32_t key_bytes,
                   uint32_t input_bytes,
                   uint32_t iv_bytes,
                   uint32_t ekey[MAX_KEY_BYTES],
                   uint8_t iv[MAX_IV_BYTES],
                   uint8_t in[MAX_IN_BYTES],
                   uint8_t out[MAX_IN_BYTES])
{
    uint8_t in_mem[BLOCK_BYTES];
#ifdef UPDATE_HW_SUPPORT
    static uint8_t iv_mem[BLOCK_BYTES];
    static uint8_t out_mem[BLOCK_BYTES];
#else // UPDATE_SW_SUPPORT
    uint8_t iv_mem[BLOCK_BYTES];
    uint8_t out_mem[BLOCK_BYTES];
#endif // UPDATE_HW_SUPPORT

    if (encryption == ENCRYPTION_MODE)
    {
#ifdef UPDATE_HW_SUPPORT
        if (iv_bytes != 0)
#endif // UPDATE_HW_SUPPORT
            memcpy_mntr<uint8_t>(out_mem, iv, BLOCK_BYTES);

        for (unsigned n = 0; n < input_bytes; n += BLOCK_BYTES)
        {
            #pragma HLS loop_tripcount min=1 max=16

            memcpy_mntr<uint8_t>(in_mem, &(in[n]), BLOCK_BYTES);

            for (unsigned i = 0; i < BLOCK_BYTES; ++i)
                in_mem[i] = in_mem[i] ^ out_mem[i];

            aes_encrypt(key_bytes, in_mem, out_mem, ekey);

            memcpy_mntr<uint8_t>(&(out[n]), out_mem, BLOCK_BYTES);
        }
    }
    else if (encryption == DECRYPTION_MODE)
    {
#ifdef UPDATE_HW_SUPPORT
        if (iv_bytes != 0)
#endif // UPDATE_HW_SUPPORT
            memcpy_mntr<uint8_t>(iv_mem, iv, BLOCK_BYTES);

        for (unsigned n = 0; n < input_bytes; n += BLOCK_BYTES)
        {
            #pragma HLS loop_tripcount min=1 max=16

            memcpy_mntr<uint8_t>(in_mem, &(in[n]), BLOCK_BYTES);

            aes_decrypt(key_bytes, in_mem, out_mem, ekey);

            for (unsigned i = 0; i < BLOCK_BYTES; ++i)
                out_mem[i] = out_mem[i] ^ iv_mem[i];

            for (unsigned i = 0; i < BLOCK_BYTES; ++i)
                iv_mem[i] = in_mem[i];

            memcpy_mntr<uint8_t>(&(out[n]), out_mem, BLOCK_BYTES);
        }
    }

    return 0;
}

#endif /* __CBC_H__ */
