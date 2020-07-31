#ifndef __EXP_H__
#define __EXP_H__

void aes_expand(uint32_t encryption,
                uint32_t key_bytes,
                uint8_t key[MAX_KEY_BYTES],
                uint32_t ekey[EXP_KEY_SIZE])
{
    int i, j;
//#ifndef C_SIMULATION
//    ac_int<32, false> temp;
//    #define range(x, y, z) x.range(y, z)
//#else // !C_SIMULATION
    uint32_t temp;
    #define range(x, y, z) ((x >> z) & 0xff)
//#endif // C_SIMULATION

    GET32(ekey[0], key + 0);
    GET32(ekey[1], key + 4);
    GET32(ekey[2], key + 8);
    GET32(ekey[3], key + 12);

    if (key_bytes == 16)
    {
        i = 0;
        for (j = 0; j < 40; j += 4)
        {
            /* #pragma HLS pipeline II=1 */
            temp = ekey[j + 3];
            ekey[j + 4] = ekey[j + 0] ^
                        (Te2[range(temp, 23, 16)] & 0xff000000) ^
                        (Te3[range(temp, 15,  8)] & 0x00ff0000) ^
                        (Te0[range(temp,  7,  0)] & 0x0000ff00) ^
                        (Te1[range(temp, 31, 24)] & 0x000000ff) ^ rcon[i++];
            ekey[j + 5] = ekey[j + 1] ^ ekey[j + 4];
            ekey[j + 6] = ekey[j + 2] ^ ekey[j + 5];
            ekey[j + 7] = temp        ^ ekey[j + 6];
        }
    }
    else if (key_bytes == 24)
    {
        GET32(ekey[4], key + 16);
        GET32(ekey[5], key + 20);

        i = 0;
        for (j = 0; j < 48; j += 6)
        {
            /* #pragma HLS pipeline II=1 */

            temp = ekey[j + 5];
            ekey[j + 6] = ekey[j + 0] ^
                        (Te2[range(temp, 23, 16)] & 0xff000000) ^
                        (Te3[range(temp, 15,  8)] & 0x00ff0000) ^
                        (Te0[range(temp,  7,  0)] & 0x0000ff00) ^
                        (Te1[range(temp, 31, 24)] & 0x000000ff) ^ rcon[i++];
            ekey[j +  7] = ekey[j + 1] ^ ekey[j + 6];
            ekey[j +  8] = ekey[j + 2] ^ ekey[j + 7];
            ekey[j +  9] = ekey[j + 3] ^ ekey[j + 8];
            ekey[j + 10] = ekey[j + 4] ^ ekey[j + 9];
            ekey[j + 11] = ekey[j + 5] ^ ekey[j + 10];
        }
    }
    else if (key_bytes == 32)
    {
        GET32(ekey[4], key + 16);
        GET32(ekey[5], key + 20);
        GET32(ekey[6], key + 24);
        GET32(ekey[7], key + 28);

       i = 0;
       for (j = 0; j < 56; j += 8)
       {
           /* #pragma HLS pipeline II=1 */

            temp = ekey[j + 7];
            ekey[j + 8] = ekey[j + 0] ^
                          (Te2[range(temp, 23, 16)] & 0xff000000) ^
                          (Te3[range(temp, 15,  8)] & 0x00ff0000) ^
                          (Te0[range(temp,  7,  0)] & 0x0000ff00) ^
                          (Te1[range(temp, 31, 24)] & 0x000000ff) ^ rcon[i++];
            ekey[j +  9] = ekey[j + 1] ^ ekey[j +  8];
            ekey[j + 10] = ekey[j + 2] ^ ekey[j +  9];
            ekey[j + 11] = ekey[j + 3] ^ ekey[j + 10];

            if (j != 48)
            {
                temp = ekey[j + 11];
                ekey[j + 12] = ekey[j + 4] ^
                             (Te2[range(temp, 31, 24)] & 0xff000000) ^
                             (Te3[range(temp, 23, 16)] & 0x00ff0000) ^
                             (Te0[range(temp, 15,  8)] & 0x0000ff00) ^
                             (Te1[range(temp,  7,  0)] & 0x000000ff);
                ekey[j + 13] = ekey[j + 5] ^ ekey[j + 12];
                ekey[j + 14] = ekey[j + 6] ^ ekey[j + 13];
                ekey[j + 15] = ekey[j + 7] ^ ekey[j + 14];
            }
        }
    }

#define SWAP(var1, var2, tmp) \
    { tmp = var1; var1 = var2; var2 = tmp; }

    if (encryption == DECRYPTION_MODE)
    {
        uint32_t tmp1, tmp2, tmp3, tmp4;

        if (key_bytes == 16)
        {
            for (i = 0; i < 20; i += 4)
            {
                /* #pragma HLS pipeline II=1 */
                #pragma HLS unroll skip_exit_check

                SWAP(ekey[i + 0], ekey[40 - i], tmp1);
                SWAP(ekey[i + 1], ekey[41 - i], tmp2);
                SWAP(ekey[i + 2], ekey[42 - i], tmp3);
                SWAP(ekey[i + 3], ekey[43 - i], tmp4);
            }

        }
        else if (key_bytes == 24)
        {
            for (i = 0; i < 24; i += 4)
            {
                /* #pragma HLS pipeline II=1 */
                #pragma HLS unroll skip_exit_check

                SWAP(ekey[i + 0], ekey[48 - i], tmp1);
                SWAP(ekey[i + 1], ekey[49 - i], tmp2);
                SWAP(ekey[i + 2], ekey[50 - i], tmp3);
                SWAP(ekey[i + 3], ekey[51 - i], tmp4);
            }
        }
        else if (key_bytes == 32)
        {
            for (i = 0; i < 28; i += 4)
            {
                /* #pragma HLS pipeline II=1 */
                #pragma HLS unroll skip_exit_check

                SWAP(ekey[i + 0], ekey[56 - i], tmp1);
                SWAP(ekey[i + 1], ekey[57 - i], tmp2);
                SWAP(ekey[i + 2], ekey[58 - i], tmp3);
                SWAP(ekey[i + 3], ekey[59 - i], tmp4);
            }
        }

        for (j = 4; j < 40; ++j)
        {
            #pragma HLS unroll skip_exit_check

            ekey[j] = Td0[Te1[(ekey[j] >> 24) & 0xff] & 0xff] ^
                      Td1[Te1[(ekey[j] >> 16) & 0xff] & 0xff] ^
                      Td2[Te1[(ekey[j] >>  8) & 0xff] & 0xff] ^
                      Td3[Te1[(ekey[j] >>  0) & 0xff] & 0xff];
        }

        if (key_bytes >= 24)
        {
            for (j = 40; j < 48; ++j)
            {
                #pragma HLS unroll skip_exit_check

                ekey[j] = Td0[Te1[(ekey[j] >> 24) & 0xff] & 0xff] ^
                          Td1[Te1[(ekey[j] >> 16) & 0xff] & 0xff] ^
                          Td2[Te1[(ekey[j] >>  8) & 0xff] & 0xff] ^
                          Td3[Te1[(ekey[j] >>  0) & 0xff] & 0xff];
            }
        }

        if (key_bytes >= 32)
        {
            for (j = 48; j < 56; ++j)
            {
                #pragma HLS unroll skip_exit_check

                ekey[j] = Td0[Te1[(ekey[j] >> 24) & 0xff] & 0xff] ^
                          Td1[Te1[(ekey[j] >> 16) & 0xff] & 0xff] ^
                          Td2[Te1[(ekey[j] >>  8) & 0xff] & 0xff] ^
                          Td3[Te1[(ekey[j] >>  0) & 0xff] & 0xff];
            }
        }
    }
}

#endif /* __EXP_H__ */
