#ifndef __DEC_H__
#define __DEC_H__

void aes_decrypt(uint32_t key_bytes,
                 uint8_t in[BLOCK_BYTES],
                 uint8_t out[BLOCK_BYTES],
                 uint32_t ekey[EXP_KEY_SIZE])
{
    #pragma HLS inline
    #pragma HLS pipeline

    int i = 0, j = 0;
//#ifndef C_SIMULATION
//    ac_int<32, false> s0, s1, s2, s3;
//    ac_int<32, false> t0, t1, t2, t3;
//    #define range(x, y, z) x.range(y, z)
//#else /* !C_SIMULATION */
    uint32_t s0, s1, s2, s3;
    uint32_t t0, t1, t2, t3;
    #define range(x, y, z) ((x >> z) & 0xff)
//#endif /* C_SIMULATION */

    #pragma HLS array_partition variable=in cyclic factor=16
    #pragma HLS array_partition variable=out cyclic factor=16
    #pragma HLS array_partition variable=ekey cyclic factor=8

    #pragma HLS resource variable=Td0 core=ROM_nP_BRAM
    #pragma HLS resource variable=Td1 core=ROM_nP_BRAM
    #pragma HLS resource variable=Td2 core=ROM_nP_BRAM
    #pragma HLS resource variable=Td3 core=ROM_nP_BRAM
    #pragma HLS resource variable=Td4 core=ROM_nP_BRAM

    GET32(s0, in +  0) ^ ekey[0];
    GET32(s1, in +  4) ^ ekey[1];
    GET32(s2, in +  8) ^ ekey[2];
    GET32(s3, in + 12) ^ ekey[3];

    for (i = 0; i < 5; i += 1, j += 8)
    {
        #pragma HLS unroll complete

        t0 = Td0[range(s0, 31, 24)] ^
             Td1[range(s3, 23, 16)] ^
             Td2[range(s2, 15,  8)] ^
             Td3[range(s1,  7,  0)] ^ ekey[j + 4];
        t1 = Td0[range(s1, 31, 24)] ^
             Td1[range(s0, 23, 16)] ^
             Td2[range(s3, 15,  8)] ^
             Td3[range(s2,  7,  0)] ^ ekey[j + 5];
        t2 = Td0[range(s2, 31, 24)] ^
             Td1[range(s1, 23, 16)] ^
             Td2[range(s0, 15,  8)] ^
             Td3[range(s3,  7,  0)] ^ ekey[j + 6];
        t3 = Td0[range(s3, 31, 24)] ^
             Td1[range(s2, 23, 16)] ^
             Td2[range(s1, 15,  8)] ^
             Td3[range(s0,  7,  0)] ^ ekey[j + 7];

        s0 = Td0[range(t0, 31, 24)] ^
             Td1[range(t3, 23, 16)] ^
             Td2[range(t2, 15,  8)] ^
             Td3[range(t1,  7,  0)] ^ ekey[j + 8];
        s1 = Td0[range(t1, 31, 24)] ^
             Td1[range(t0, 23, 16)] ^
             Td2[range(t3, 15,  8)] ^
             Td3[range(t2,  7,  0)] ^ ekey[j + 9];
        s2 = Td0[range(t2, 31, 24)] ^
             Td1[range(t1, 23, 16)] ^
             Td2[range(t0, 15,  8)] ^
             Td3[range(t3,  7,  0)] ^ ekey[j + 10];
        s3 = Td0[range(t3, 31, 24)] ^
             Td1[range(t2, 23, 16)] ^
             Td2[range(t1, 15,  8)] ^
             Td3[range(t0,  7,  0)] ^ ekey[j + 11];
    }

    if (key_bytes >= 24)
    {
        t0 = Td0[range(s0, 31, 24)] ^
             Td1[range(s3, 23, 16)] ^
             Td2[range(s2, 15,  8)] ^
             Td3[range(s1,  7,  0)] ^ ekey[44];
        t1 = Td0[range(s1, 31, 24)] ^
             Td1[range(s0, 23, 16)] ^
             Td2[range(s3, 15,  8)] ^
             Td3[range(s2,  7,  0)] ^ ekey[45];
        t2 = Td0[range(s2, 31, 24)] ^
             Td1[range(s1, 23, 16)] ^
             Td2[range(s0, 15,  8)] ^
             Td3[range(s3,  7,  0)] ^ ekey[46];
        t3 = Td0[range(s3, 31, 24)] ^
             Td1[range(s2, 23, 16)] ^
             Td2[range(s1, 15,  8)] ^
             Td3[range(s0,  7,  0)] ^ ekey[47];

        s0 = Td0[range(t0, 31, 24)] ^
             Td1[range(t3, 23, 16)] ^
             Td2[range(t2, 15,  8)] ^
             Td3[range(t1,  7,  0)] ^ ekey[48];
        s1 = Td0[range(t1, 31, 24)] ^
             Td1[range(t0, 23, 16)] ^
             Td2[range(t3, 15,  8)] ^
             Td3[range(t2,  7,  0)] ^ ekey[49];
        s2 = Td0[range(t2, 31, 24)] ^
             Td1[range(t1, 23, 16)] ^
             Td2[range(t0, 15,  8)] ^
             Td3[range(t3,  7,  0)] ^ ekey[50];
        s3 = Td0[range(t3, 31, 24)] ^
             Td1[range(t2, 23, 16)] ^
             Td2[range(t1, 15,  8)] ^
             Td3[range(t0,  7,  0)] ^ ekey[51];

        j += 8;
    }

    if (key_bytes >= 32)
    {
        t0 = Td0[range(s0, 31, 24)] ^
             Td1[range(s3, 23, 16)] ^
             Td2[range(s2, 15,  8)] ^
             Td3[range(s1,  7,  0)] ^ ekey[52];
        t1 = Td0[range(s1, 31, 24)] ^
             Td1[range(s0, 23, 16)] ^
             Td2[range(s3, 15,  8)] ^
             Td3[range(s2,  7,  0)] ^ ekey[53];
        t2 = Td0[range(s2, 31, 24)] ^
             Td1[range(s1, 23, 16)] ^
             Td2[range(s0, 15,  8)] ^
             Td3[range(s3,  7,  0)] ^ ekey[54];
        t3 = Td0[range(s3, 31, 24)] ^
             Td1[range(s2, 23, 16)] ^
             Td2[range(s1, 15,  8)] ^
             Td3[range(s0,  7,  0)] ^ ekey[55];

        s0 = Td0[range(t0, 31, 24)] ^
             Td1[range(t3, 23, 16)] ^
             Td2[range(t2, 15,  8)] ^
             Td3[range(t1,  7,  0)] ^ ekey[56];
        s1 = Td0[range(t1, 31, 24)] ^
             Td1[range(t0, 23, 16)] ^
             Td2[range(t3, 15,  8)] ^
             Td3[range(t2,  7,  0)] ^ ekey[57];
        s2 = Td0[range(t2, 31, 24)] ^
             Td1[range(t1, 23, 16)] ^
             Td2[range(t0, 15,  8)] ^
             Td3[range(t3,  7,  0)] ^ ekey[58];
        s3 = Td0[range(t3, 31, 24)] ^
             Td1[range(t2, 23, 16)] ^
             Td2[range(t1, 15,  8)] ^
             Td3[range(t0,  7,  0)] ^ ekey[59];

        j += 8;
    }

    s0 = (Td4[range(t0, 31, 24)] << 24) ^
         (Td4[range(t3, 23, 16)] << 16) ^
         (Td4[range(t2, 15,  8)] <<  8) ^
         (Td4[range(t1,  7,  0)] <<  0) ^ ekey[j +0];
    s1 = (Td4[range(t1, 31, 24)] << 24) ^
         (Td4[range(t0, 23, 16)] << 16) ^
         (Td4[range(t3, 15,  8)] <<  8) ^
         (Td4[range(t2,  7,  0)] <<  0) ^ ekey[j +1];
    s2 = (Td4[range(t2, 31, 24)] << 24) ^
         (Td4[range(t1, 23, 16)] << 16) ^
         (Td4[range(t0, 15,  8)] <<  8) ^
         (Td4[range(t3,  7,  0)] <<  0) ^ ekey[j +2];
    s3 = (Td4[range(t3, 31, 24)] << 24) ^
         (Td4[range(t2, 23, 16)] << 16) ^
         (Td4[range(t1, 15,  8)] <<  8) ^
         (Td4[range(t0,  7,  0)] <<  0) ^ ekey[j +3];

    PUT32(out +  0, s0);
    PUT32(out +  4, s1);
    PUT32(out +  8, s2);
    PUT32(out + 12, s3);
}

#ifndef C_SIMULATION
#undef range
#endif /* C_SIMULATION */

#endif /* __DEC_H__ */
