#ifndef __ENC_H__
#define __ENC_H__

void aes_encrypt(uint32_t key_bytes,
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

    #pragma HLS array_partition variable=Te0 cyclic factor=4
    #pragma HLS array_partition variable=Te1 cyclic factor=4
    #pragma HLS array_partition variable=Te2 cyclic factor=4
    #pragma HLS array_partition variable=Te3 cyclic factor=4

    GET32(s0, in +  0) ^ ekey[0];
    GET32(s1, in +  4) ^ ekey[1];
    GET32(s2, in +  8) ^ ekey[2];
    GET32(s3, in + 12) ^ ekey[3];

    for (i = 0; i < 5; i += 1)
    {
        #pragma HLS unroll complete

        t0 = Te0[range(s0, 31, 24)] ^
             Te1[range(s1, 23, 16)] ^
             Te2[range(s2, 15,  8)] ^
             Te3[range(s3,  7,  0)] ^ ekey[j + 4];
        t1 = Te0[range(s1, 31, 24)] ^
             Te1[range(s2, 23, 16)] ^
             Te2[range(s3, 15,  8)] ^
             Te3[range(s0,  7,  0)] ^ ekey[j + 5];
        t2 = Te0[range(s2, 31, 24)] ^
             Te1[range(s3, 23, 16)] ^
             Te2[range(s0, 15,  8)] ^
             Te3[range(s1,  7,  0)] ^ ekey[j + 6];
        t3 = Te0[range(s3, 31, 24)] ^
             Te1[range(s0, 23, 16)] ^
             Te2[range(s1, 15,  8)] ^
             Te3[range(s2,  7,  0)] ^ ekey[j + 7];

        s0 = Te0[range(t0, 31, 24)] ^
             Te1[range(t1, 23, 16)] ^
             Te2[range(t2, 15,  8)] ^
             Te3[range(t3,  7,  0)] ^ ekey[j + 8];
        s1 = Te0[range(t1, 31, 24)] ^
             Te1[range(t2, 23, 16)] ^
             Te2[range(t3, 15,  8)] ^
             Te3[range(t0,  7,  0)] ^ ekey[j + 9];
        s2 = Te0[range(t2, 31, 24)] ^
             Te1[range(t3, 23, 16)] ^
             Te2[range(t0, 15,  8)] ^
             Te3[range(t1,  7,  0)] ^ ekey[j + 10];
        s3 = Te0[range(t3, 31, 24)] ^
             Te1[range(t0, 23, 16)] ^
             Te2[range(t1, 15,  8)] ^
             Te3[range(t2,  7,  0)] ^ ekey[j + 11];

        j += 8;
    }

    if (key_bytes >= 24)
    {
        t0 = Te0[range(s0, 31, 24)] ^
             Te1[range(s1, 23, 16)] ^
             Te2[range(s2, 15,  8)] ^
             Te3[range(s3,  7,  0)] ^ ekey[44];
        t1 = Te0[range(s1, 31, 24)] ^
             Te1[range(s2, 23, 16)] ^
             Te2[range(s3, 15,  8)] ^
             Te3[range(s0,  7,  0)] ^ ekey[45];
        t2 = Te0[range(s2, 31, 24)] ^
             Te1[range(s3, 23, 16)] ^
             Te2[range(s0, 15,  8)] ^
             Te3[range(s1,  7,  0)] ^ ekey[46];
        t3 = Te0[range(s3, 31, 24)] ^
             Te1[range(s0, 23, 16)] ^
             Te2[range(s1, 15,  8)] ^
             Te3[range(s2,  7,  0)] ^ ekey[47];

        s0 = Te0[range(t0, 31, 24)] ^
             Te1[range(t1, 23, 16)] ^
             Te2[range(t2, 15,  8)] ^
             Te3[range(t3,  7,  0)] ^ ekey[48];
        s1 = Te0[range(t1, 31, 24)] ^
             Te1[range(t2, 23, 16)] ^
             Te2[range(t3, 15,  8)] ^
             Te3[range(t0,  7,  0)] ^ ekey[49];
        s2 = Te0[range(t2, 31, 24)] ^
             Te1[range(t3, 23, 16)] ^
             Te2[range(t0, 15,  8)] ^
             Te3[range(t1,  7,  0)] ^ ekey[50];
        s3 = Te0[range(t3, 31, 24)] ^
             Te1[range(t0, 23, 16)] ^
             Te2[range(t1, 15,  8)] ^
             Te3[range(t2,  7,  0)] ^ ekey[51];

        j += 8;
    }

    if (key_bytes == 32)
    {
        t0 = Te0[range(s0, 31, 24)] ^
             Te1[range(s1, 23, 16)] ^
             Te2[range(s2, 15,  8)] ^
             Te3[range(s3,  7,  0)] ^ ekey[52];
        t1 = Te0[range(s1, 31, 24)] ^
             Te1[range(s2, 23, 16)] ^
             Te2[range(s3, 15,  8)] ^
             Te3[range(s0,  7,  0)] ^ ekey[53];
        t2 = Te0[range(s2, 31, 24)] ^
             Te1[range(s3, 23, 16)] ^
             Te2[range(s0, 15,  8)] ^
             Te3[range(s1,  7,  0)] ^ ekey[54];
        t3 = Te0[range(s3, 31, 24)] ^
             Te1[range(s0, 23, 16)] ^
             Te2[range(s1, 15,  8)] ^
             Te3[range(s2,  7,  0)] ^ ekey[55];

        s0 = Te0[range(t0, 31, 24)] ^
             Te1[range(t1, 23, 16)] ^
             Te2[range(t2, 15,  8)] ^
             Te3[range(t3,  7,  0)] ^ ekey[56];
        s1 = Te0[range(t1, 31, 24)] ^
             Te1[range(t2, 23, 16)] ^
             Te2[range(t3, 15,  8)] ^
             Te3[range(t0,  7,  0)] ^ ekey[57];
        s2 = Te0[range(t2, 31, 24)] ^
             Te1[range(t3, 23, 16)] ^
             Te2[range(t0, 15,  8)] ^
             Te3[range(t1,  7,  0)] ^ ekey[58];
        s3 = Te0[range(t3, 31, 24)] ^
             Te1[range(t0, 23, 16)] ^
             Te2[range(t1, 15,  8)] ^
             Te3[range(t2,  7,  0)] ^ ekey[59];

        j += 8;
    }

    s0 = (Te2[range(t0, 31, 24)] & 0xff000000) ^
         (Te3[range(t1, 23, 16)] & 0x00ff0000) ^
         (Te0[range(t2, 15,  8)] & 0x0000ff00) ^
         (Te1[range(t3,  7,  0)] & 0x000000ff) ^ ekey[j + 0];
    s1 = (Te2[range(t1, 31, 24)] & 0xff000000) ^
         (Te3[range(t2, 23, 16)] & 0x00ff0000) ^
         (Te0[range(t3, 15,  8)] & 0x0000ff00) ^
         (Te1[range(t0,  7,  0)] & 0x000000ff) ^ ekey[j + 1];
    s2 = (Te2[range(t2, 31, 24)] & 0xff000000) ^
         (Te3[range(t3, 23, 16)] & 0x00ff0000) ^
         (Te0[range(t0, 15,  8)] & 0x0000ff00) ^
         (Te1[range(t1,  7,  0)] & 0x000000ff) ^ ekey[j + 2];
    s3 = (Te2[range(t3, 31, 24)] & 0xff000000) ^
         (Te3[range(t0, 23, 16)] & 0x00ff0000) ^
         (Te0[range(t1, 15,  8)] & 0x0000ff00) ^
         (Te1[range(t2,  7,  0)] & 0x000000ff) ^ ekey[j + 3];

    PUT32(out +  0, s0);
    PUT32(out +  4, s1);
    PUT32(out +  8, s2);
    PUT32(out + 12, s3);
}

#ifndef C_SIMULATION
#undef range
#endif /* C_SIMULATION */

#endif /* __ENC_H__ */
