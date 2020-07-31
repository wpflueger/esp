#ifndef __GCM_TESTS_H__
#define __GCM_TESTS_H__

#include "aes.h"
#include "utils.h"

/* GCM Tests */

#define GCMENCINT128_VERBOSE 0
#define GCMENCINT192_VERBOSE 0
#define GCMENCINT256_VERBOSE 0

#define GCMENCEXT128_VERBOSE 0
#define GCMENCEXT192_VERBOSE 0
#define GCMENCEXT256_VERBOSE 0

#define GCMDEC128_VERBOSE 0
#define GCMDEC192_VERBOSE 0
#define GCMDEC256_VERBOSE 0

/* Wrapper for function call */

#define AES_GCM_UPDATE(mode, klen, ivlen, ilen, aadlen, key, iv, in, out, aad, ret) \
    aes(GCM_OPERATION_MODE, mode, klen, ivlen, ilen, aadlen, 0, key, iv, in, out, aad, NULL, ret)

#define AES_GCM_FINAL(mode, klen, taglen, key, tag, ret) \
    aes(GCM_OPERATION_MODE, mode, klen, 0, 0, 0, taglen, key, NULL, NULL, NULL, NULL, tag, ret)

/*****************************************************************************/

int gcm_int128(void)
{
    unsigned int i;
    uint8_t *buffer;
    uint8_t *buffer_t;
    unsigned test_passed = 0;
    
    int ret = 0;

    cavp_data cavp;

#ifdef C_SIMULATION
    parse_cavp(&cavp, "../tests/gcm/gcmEncryptIntIV128.rsp", GCM_OPERATION_MODE);
#else // VIVADO_HLS
    parse_cavp(&cavp, "../../../../../tests/gcm/gcmEncryptIntIV128.rsp", GCM_OPERATION_MODE);
#endif // C_SIMULATION

    for (i = 0; i < cavp.tot_tests; ++i)
    {
        buffer   = (uint8_t *) malloc((sizeof(uint8_t) * cavp.lp[i]).to_uint64());
        buffer_t = (uint8_t *) malloc((sizeof(uint8_t) * 10 * cavp.lt[i]).to_uint64());

        /* This allows to test the init-update-doFinal paradigm. */

        if (cavp.lp[i] == 0)
        {
            AES_GCM_UPDATE(ENCRYPTION_MODE, 128 / 8, cavp.li[i], 0, cavp.la[i],
                    cavp.k[i], cavp.i[i], cavp.p[i], buffer, cavp.a[i], ret);
        }
        else
        {
            for (unsigned k = 0; k < cavp.lp[i]; k += 16)
            {
                unsigned len = (k + 16 <= cavp.lc[i]) ? 16 : (cavp.lc[i] - k).to_uint64();

                AES_GCM_UPDATE(ENCRYPTION_MODE, 128 / 8, cavp.li[i], len, cavp.la[i],
                        cavp.k[i], cavp.i[i], &(cavp.p[i][k]), &(buffer[k]), cavp.a[i], ret);
            }
        }

        AES_GCM_FINAL(ENCRYPTION_MODE, 128 / 8, cavp.lt[i], cavp.k[i], buffer_t, ret);

        test_passed += eval_cavp(&cavp, buffer, buffer_t, i, true,
                0, GCM_OPERATION_MODE, GCMENCINT128_VERBOSE);

        free(buffer_t);
        free(buffer);
    }

    printf("Info: test passed #%u out of #%u (GCMENCINT128)\n",
            test_passed, cavp.tot_tests);

    free_cavp(&cavp, GCM_OPERATION_MODE);
    return cavp.tot_tests - test_passed;
}

int gcm_int192(void)
{
    unsigned int i;
    uint8_t *buffer;
    uint8_t *buffer_t;
    unsigned test_passed = 0;
    
    int ret = 0;

    cavp_data cavp;

#ifdef C_SIMULATION
    parse_cavp(&cavp, "../tests/gcm/gcmEncryptIntIV192.rsp", GCM_OPERATION_MODE);
#else // VIVADO_HLS
    parse_cavp(&cavp, "../../../../../tests/gcm/gcmEncryptIntIV192.rsp", GCM_OPERATION_MODE);
#endif // C_SIMULATION

    for (i = 0; i < cavp.tot_tests; ++i)
    {
        buffer   = (uint8_t *) malloc((sizeof(uint8_t) * cavp.lp[i]).to_uint64());
        buffer_t = (uint8_t *) malloc((sizeof(uint8_t) * 10 * cavp.lt[i]).to_uint64());

        AES_GCM_UPDATE(ENCRYPTION_MODE, 192 / 8, cavp.li[i], cavp.lp[i], cavp.la[i],
            cavp.k[i], cavp.i[i], cavp.p[i], buffer, cavp.a[i], ret);

        AES_GCM_FINAL(ENCRYPTION_MODE, 192 / 8, cavp.lt[i], cavp.k[i], buffer_t, ret);

        test_passed += eval_cavp(&cavp, buffer, buffer_t, i, true,
                0, GCM_OPERATION_MODE, GCMENCINT192_VERBOSE);

        free(buffer_t);
        free(buffer);
    }

    printf("Info: test passed #%u out of #%u (GCMENCINT192)\n",
            test_passed, cavp.tot_tests);

    free_cavp(&cavp, GCM_OPERATION_MODE);
    return cavp.tot_tests - test_passed;
}

int gcm_int256(void)
{
    unsigned int i;
    uint8_t *buffer;
    uint8_t *buffer_t;
    unsigned test_passed = 0;
    
    int ret = 0;

    cavp_data cavp;

#ifdef C_SIMULATION
    parse_cavp(&cavp, "../tests/gcm/gcmEncryptIntIV256.rsp", GCM_OPERATION_MODE);
#else // VIVADO_HLS
    parse_cavp(&cavp, "../../../../../tests/gcm/gcmEncryptIntIV256.rsp", GCM_OPERATION_MODE);
#endif // C_SIMULATION

    for (i = 0; i < cavp.tot_tests; ++i)
    {
        buffer   = (uint8_t *) malloc((sizeof(uint8_t) * cavp.lp[i]).to_uint64());
        buffer_t = (uint8_t *) malloc((sizeof(uint8_t) * 10 * cavp.lt[i]).to_uint64());

        AES_GCM_UPDATE(ENCRYPTION_MODE, 256 / 8, cavp.li[i], cavp.lp[i], cavp.la[i],
            cavp.k[i], cavp.i[i], cavp.p[i], buffer, cavp.a[i], ret);

        AES_GCM_FINAL(ENCRYPTION_MODE, 256 / 8, cavp.lt[i], cavp.k[i], buffer_t, ret);

        test_passed += eval_cavp(&cavp, buffer, buffer_t, i, true,
                0, GCM_OPERATION_MODE, GCMENCINT256_VERBOSE);

        free(buffer_t);
        free(buffer);
    }

    printf("Info: test passed #%u out of #%u (GCMENCINT256)\n",
            test_passed, cavp.tot_tests);

    free_cavp(&cavp, GCM_OPERATION_MODE);
    return cavp.tot_tests - test_passed;
}

/*****************************************************************************/

int gcm_ext128(void)
{
    unsigned int i;
    uint8_t *buffer;
    uint8_t *buffer_t;
    unsigned test_passed = 0;
    
    int ret = 0;

    cavp_data cavp;

#ifdef C_SIMULATION
    parse_cavp(&cavp, "../tests/gcm/gcmEncryptExtIV128.rsp", GCM_OPERATION_MODE);
#else // VIVADO_HLS
    parse_cavp(&cavp, "../../../../../tests/gcm/gcmEncryptExtIV128.rsp", GCM_OPERATION_MODE);
#endif // C_SIMULATION

    for (i = 0; i < cavp.tot_tests; ++i)
    {
        buffer   = (uint8_t *) malloc((sizeof(uint8_t) * cavp.lp[i]).to_uint64());
        buffer_t = (uint8_t *) malloc((sizeof(uint8_t) * 10 * cavp.lt[i]).to_uint64());

        AES_GCM_UPDATE(ENCRYPTION_MODE, 128 / 8, cavp.li[i], cavp.lp[i], cavp.la[i],
            cavp.k[i], cavp.i[i], cavp.p[i], buffer, cavp.a[i], ret);

        AES_GCM_FINAL(ENCRYPTION_MODE, 128 / 8, cavp.lt[i], cavp.k[i], buffer_t, ret);

        test_passed += eval_cavp(&cavp, buffer, buffer_t, i, true,
                0, GCM_OPERATION_MODE, GCMENCEXT128_VERBOSE);

        free(buffer_t);
        free(buffer);
    }

    printf("Info: test passed #%u out of #%u (GCMENCEXT128)\n",
            test_passed, cavp.tot_tests);

    free_cavp(&cavp, GCM_OPERATION_MODE);
    return cavp.tot_tests - test_passed;
}

int gcm_ext192(void)
{
    unsigned int i;
    uint8_t *buffer;
    uint8_t *buffer_t;
    unsigned test_passed = 0;
    
    int ret;

    cavp_data cavp;

#ifdef C_SIMULATION
    parse_cavp(&cavp, "../tests/gcm/gcmEncryptExtIV192.rsp", GCM_OPERATION_MODE);
#else // VIVADO_HLS
    parse_cavp(&cavp, "../../../../../tests/gcm/gcmEncryptExtIV192.rsp", GCM_OPERATION_MODE);
#endif // C_SIMULATION

    for (i = 0; i < cavp.tot_tests; ++i)
    {
        buffer   = (uint8_t *) malloc((sizeof(uint8_t) * cavp.lp[i]).to_uint64());
        buffer_t = (uint8_t *) malloc((sizeof(uint8_t) * 10 * cavp.lt[i]).to_uint64());

        AES_GCM_UPDATE(ENCRYPTION_MODE, 192 / 8, cavp.li[i], cavp.lp[i], cavp.la[i],
            cavp.k[i], cavp.i[i], cavp.p[i], buffer, cavp.a[i], ret);

        AES_GCM_FINAL(ENCRYPTION_MODE, 192 / 8, cavp.lt[i], cavp.k[i], buffer_t, ret);

        test_passed += eval_cavp(&cavp, buffer, buffer_t, i, true,
                0, GCM_OPERATION_MODE, GCMENCEXT192_VERBOSE);

        free(buffer_t);
        free(buffer);
    }

    printf("Info: test passed #%u out of #%u (GCMENCEXT192)\n",
            test_passed, cavp.tot_tests);

    free_cavp(&cavp, GCM_OPERATION_MODE);
    return cavp.tot_tests - test_passed;
}

int gcm_ext256(void)
{
    unsigned int i;
    uint8_t *buffer;
    uint8_t *buffer_t;
    unsigned test_passed = 0;
    
    int ret = 0;

    cavp_data cavp;

#ifdef C_SIMULATION
    parse_cavp(&cavp, "../tests/gcm/gcmEncryptExtIV256.rsp", GCM_OPERATION_MODE);
#else // VIVADO_HLS
    parse_cavp(&cavp, "../../../../../tests/gcm/gcmEncryptExtIV256.rsp", GCM_OPERATION_MODE);
#endif // C_SIMULATION

    for (i = 0; i < cavp.tot_tests; ++i)
    {
        buffer   = (uint8_t *) malloc((sizeof(uint8_t) * cavp.lp[i]).to_uint64());
        buffer_t = (uint8_t *) malloc((sizeof(uint8_t) * 10 * cavp.lt[i]).to_uint64());

        AES_GCM_UPDATE(ENCRYPTION_MODE, 256 / 8, cavp.li[i], cavp.lp[i], cavp.la[i],
            cavp.k[i], cavp.i[i], cavp.p[i], buffer, cavp.a[i], ret);

        AES_GCM_FINAL(ENCRYPTION_MODE, 256 / 8, cavp.lt[i], cavp.k[i], buffer_t, ret);

        test_passed += eval_cavp(&cavp, buffer, buffer_t, i, true,
                0, GCM_OPERATION_MODE, GCMENCEXT256_VERBOSE);

        free(buffer_t);
        free(buffer);
    }

    printf("Info: test passed #%u out of #%u (GCMENCEXT256)\n",
            test_passed, cavp.tot_tests);

    free_cavp(&cavp, GCM_OPERATION_MODE);
    return cavp.tot_tests - test_passed;
}

/*****************************************************************************/

int gcm_dec128(void)
{
    int ret;
    unsigned int i;
    uint8_t *buffer;
    unsigned test_passed = 0;

    cavp_data cavp;

#ifdef C_SIMULATION
    parse_cavp(&cavp, "../tests/gcm/gcmDecrypt128.rsp", GCM_OPERATION_MODE);
#else // VIVADO_HLS
    parse_cavp(&cavp, "../../../../../tests/gcm/gcmDecrypt128.rsp", GCM_OPERATION_MODE);
#endif // C_SIMULATION

    for (i = 0; i < cavp.tot_tests; ++i)
    {
        buffer = (uint8_t *) malloc((sizeof(uint8_t) * cavp.lc[i]).to_uint64());

        /* This allows to test the init-update-doFinal paradigm. */

        if (cavp.lc[i] == 0)
        {
            AES_GCM_UPDATE(DECRYPTION_MODE, 128 / 8, cavp.li[i], 0, cavp.la[i],
                    cavp.k[i], cavp.i[i], cavp.p[i], buffer, cavp.a[i], ret);
        }
        else
        {
            for (unsigned k = 0; k < cavp.lc[i]; k += 16)
            {
                unsigned len = (k + 16 <= cavp.lc[i]) ? 16 : (cavp.lc[i] - k).to_uint64();

                AES_GCM_UPDATE(DECRYPTION_MODE, 128 / 8, cavp.li[i], len, cavp.la[i],
                        cavp.k[i], cavp.i[i], &(cavp.c[i][k]), &(buffer[k]), cavp.a[i], ret);
            }
        }

        AES_GCM_FINAL(DECRYPTION_MODE, 128 / 8, cavp.lt[i], cavp.k[i], cavp.t[i], ret);

        int val = eval_cavp(&cavp, buffer, NULL, i, false, ret,
                GCM_OPERATION_MODE, GCMDEC192_VERBOSE);

        test_passed += val;
        free(buffer);
    }

    printf("Info: test passed #%u out of #%u (GCMDEC128)\n",
            test_passed, cavp.tot_tests);

    free_cavp(&cavp, GCM_OPERATION_MODE);
    return cavp.tot_tests - test_passed;
}

int gcm_dec192(void)
{
    int ret;
    unsigned int i;
    uint8_t *buffer;
    unsigned test_passed = 0;

    cavp_data cavp;

#ifdef C_SIMULATION
    parse_cavp(&cavp, "../tests/gcm/gcmDecrypt192.rsp", GCM_OPERATION_MODE);
#else // VIVADO_HLS
    parse_cavp(&cavp, "../../../../../tests/gcm/gcmDecrypt192.rsp", GCM_OPERATION_MODE);
#endif // C_SIMULATION

    for (i = 0; i < cavp.tot_tests; ++i)
    {
        buffer = (uint8_t *) malloc((sizeof(uint8_t) * cavp.lc[i]).to_uint64());

        AES_GCM_UPDATE(DECRYPTION_MODE, 192 / 8, cavp.li[i], cavp.lc[i], cavp.la[i],
            cavp.k[i], cavp.i[i], cavp.c[i], buffer, cavp.a[i], ret);

        AES_GCM_FINAL(DECRYPTION_MODE, 192 / 8, cavp.lt[i], cavp.k[i], cavp.t[i], ret);

        int val = eval_cavp(&cavp, buffer, NULL, i, false, ret,
                GCM_OPERATION_MODE, GCMDEC192_VERBOSE);

        test_passed += val;
        free(buffer);
    }

    printf("Info: test passed #%u out of #%u (GCMDEC192)\n",
            test_passed, cavp.tot_tests);

    free_cavp(&cavp, GCM_OPERATION_MODE);
    return cavp.tot_tests - test_passed;
}

int gcm_dec256(void)
{
    int ret;
    unsigned int i;
    uint8_t *buffer;
    unsigned test_passed = 0;

    cavp_data cavp;

#ifdef C_SIMULATION
    parse_cavp(&cavp, "../tests/gcm/gcmDecrypt256.rsp", GCM_OPERATION_MODE);
#else // VIVADO_HLS
    parse_cavp(&cavp, "../../../../../tests/gcm/gcmDecrypt256.rsp", GCM_OPERATION_MODE);
#endif // C_SIMULATION

    for (i = 0; i < cavp.tot_tests; ++i)
    {        
        buffer = (uint8_t *) malloc((sizeof(uint8_t) * cavp.lc[i]).to_uint64());

        AES_GCM_UPDATE(DECRYPTION_MODE, 256 / 8, cavp.li[i], cavp.lc[i], cavp.la[i],
            cavp.k[i], cavp.i[i], cavp.c[i], buffer, cavp.a[i], ret);

        AES_GCM_FINAL(DECRYPTION_MODE, 256 / 8, cavp.lt[i], cavp.k[i], cavp.t[i], ret);

        int val = eval_cavp(&cavp, buffer, NULL, i, false, ret,
                GCM_OPERATION_MODE, GCMDEC256_VERBOSE);

        test_passed += val;
        free(buffer);
    }

    printf("Info: test passed #%u out of #%u (GCMDEC256)\n",
            test_passed, cavp.tot_tests);

    free_cavp(&cavp, GCM_OPERATION_MODE);
    return cavp.tot_tests - test_passed;
}

#endif /* __GCM_TESTS_H__ */
