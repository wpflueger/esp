#ifndef __ECB_H__
#define __ECB_H__

#include "string_mntr.h"

#include "../defines.h"
#include "../exp.h"
#include "../enc.h"
#include "../dec.h"

/* Electronic Codebook (ECB) */

/* Integer Counter Mode (CTR) */

#define HUGE_INT_MAX_VALUE ((uint64_t) 0xFFFFFFFF)

void increment(uint8_t iv[BLOCK_BYTES])
{
    uint64_t tmp;
    uint64_t carry = 1;

    for (int i = BLOCK_BYTES - 1; i >= 0; --i)
    {
        tmp = iv[i] + carry;
        iv[i] = (tmp & HUGE_INT_MAX_VALUE);
        carry = (tmp > HUGE_INT_MAX_VALUE);
        if (carry == 0) break;
    }
}

void lxor(uint8_t out_mem[BLOCK_BYTES],
          uint8_t in_mem[BLOCK_BYTES])
{
    for (unsigned i = 0; i < BLOCK_BYTES; ++i)
    {
        #pragma HLS unroll complete
        out_mem[i] ^= in_mem[i];
    }
}

#define UNROLL_FACTOR 4
#define PLM_SIZE (UNROLL_FACTOR << BLOCK_BYTES_LOG)

void load_memory(uint8_t in_mem[PLM_SIZE],
                 uint8_t in[MAX_IN_BYTES],
                 uint32_t input_bytes,
                 uint32_t input_offset)
{
    /* #pragma HLS inline off */

    uint32_t diff = input_bytes - input_offset;
    uint32_t bytes = (diff >= PLM_SIZE) ? PLM_SIZE : diff;

    for (uint32_t k = 0; k < bytes; ++k)
    {
        #pragma HLS loop_tripcount min=16 max=64
        #pragma HLS pipeline II=1

        in_mem[k] = in[input_offset + k];
    }
}

void store_memory(uint8_t out_mem[PLM_SIZE],
                  uint8_t out[MAX_IN_BYTES],
                  uint32_t input_bytes,
                  uint32_t input_offset)
{
    /* #pragma HLS inline off */

    uint32_t diff = input_bytes - input_offset;
    uint32_t bytes = (diff >= PLM_SIZE) ? PLM_SIZE : diff;

    for (uint32_t k = 0; k < bytes; ++k)
    {
        #pragma HLS loop_tripcount min=16 max=64
        #pragma HLS pipeline II=1

        out[input_offset + k] = out_mem[k];
    }
}

void parallel_encryption(uint32_t key_bytes,
                         uint8_t in_mem[PLM_SIZE],
                         uint8_t out_mem[PLM_SIZE],
                         uint32_t ekey[EXP_KEY_SIZE])
{
    for (int k = 0; k < UNROLL_FACTOR; ++k)
    {
        #pragma hls unroll complete

        aes_encrypt(key_bytes, &in_mem[k  << BLOCK_BYTES_LOG],
                               &out_mem[k << BLOCK_BYTES_LOG],
                               ekey);
    }
}

void parallel_decryption(uint32_t key_bytes,
                         uint8_t in_mem[PLM_SIZE],
                         uint8_t out_mem[PLM_SIZE],
                         uint32_t ekey[EXP_KEY_SIZE])
{
    for (int k = 0; k < UNROLL_FACTOR; ++k)
    {
        #pragma hls unroll complete

        aes_decrypt(key_bytes, &in_mem[k << BLOCK_BYTES_LOG],
                               &out_mem[k << BLOCK_BYTES_LOG],
                               ekey);
    }
}

void dataflow_encryption(uint32_t key_bytes,
                         uint32_t input_bytes,
                         uint32_t input_offset,
                         uint8_t in[MAX_IN_BYTES],
                         uint8_t out[MAX_IN_BYTES],
                         uint32_t ekey[EXP_KEY_SIZE])
{
    uint8_t in_mem[PLM_SIZE];
    uint8_t out_mem[PLM_SIZE];

    #pragma HLS dataflow

    load_memory(in_mem, in, input_bytes, input_offset);
    parallel_encryption(key_bytes, in_mem, out_mem, ekey);
    store_memory(out_mem, out, input_bytes, input_offset);
}

void dataflow_decryption(uint32_t key_bytes,
                         uint32_t input_bytes,
                         uint32_t input_offset,
                         uint8_t in[MAX_IN_BYTES],
                         uint8_t out[MAX_IN_BYTES],
                         uint32_t ekey[EXP_KEY_SIZE])
{
    uint8_t in_mem[PLM_SIZE];
    uint8_t out_mem[PLM_SIZE];

    #pragma HLS dataflow

    load_memory(in_mem, in, input_bytes, input_offset);
    parallel_decryption(key_bytes, in_mem, out_mem, ekey);
    store_memory(out_mem, out, input_bytes, input_offset);
}

int aes_ecb_ctr_cipher(uint32_t oper_mode,
                       uint32_t encryption,
                       uint32_t key_bytes,
                       uint32_t iv_bytes,
                       uint32_t input_bytes,
                       uint32_t ekey[EXP_KEY_SIZE],
                       uint8_t iv[MAX_IV_BYTES],
                       uint8_t in[MAX_IN_BYTES],
                       uint8_t out[MAX_IN_BYTES])
{
#ifdef UPDATE_HW_SUPPORT
    static uint8_t in_mem[BLOCK_BYTES];
#else // UPDATE_SW_SUPPORT
    uint8_t in_mem[BLOCK_BYTES];
#endif // UPDATE_HW_SUPPORT
    uint8_t out_mem[BLOCK_BYTES];
    uint8_t tmp_mem[BLOCK_BYTES];

#ifdef UPDATE_HW_SUPPORT
    if (oper_mode == CTR_OPERATION_MODE && iv_bytes != 0)
#else // UPDATE_SW_SUPPORT
    if (oper_mode == CTR_OPERATION_MODE)
#endif // UPDATE_HW_SUPPORT
        memcpy_mntr<uint8_t>(in_mem, iv, BLOCK_BYTES);

    if (encryption == ENCRYPTION_MODE)
    {
        if (oper_mode == ECB_OPERATION_MODE)
        {
            for (unsigned offset = 0; offset < input_bytes; offset += (BLOCK_BYTES << 2))
            {
                /* Considering an input of 65536 bytes. */

                #pragma HLS loop_tripcount min=1 max=1024
                dataflow_encryption(key_bytes, input_bytes, offset, in, out, ekey);
            }
        }
        else // oper_mode == CTR_OPERATION_MODE
        {
            for (unsigned i = 0; i < input_bytes; i += BLOCK_BYTES)
            {
                /* Considering an input of 65536 bytes. */
                #pragma HLS loop_tripcount min=1 max=4096

                load_memory(tmp_mem, in, input_bytes, i);
                aes_encrypt(key_bytes, in_mem, out_mem, ekey);
                lxor(out_mem, tmp_mem); /* update out_mem */
                store_memory(out_mem, out, input_bytes, i);
                increment(in_mem);
            }
        }
    }
    else if (encryption == DECRYPTION_MODE)
    {
        for (unsigned offset = 0; offset < input_bytes; offset += (BLOCK_BYTES << 2))
        {
            /* Considering an input of 65536 bytes. */

            #pragma HLS loop_tripcount min=1 max=1024
            dataflow_decryption(key_bytes, input_bytes, offset, in, out, ekey);
        }
    }

    return 0;
}

#endif /* __ECB_H__ */
