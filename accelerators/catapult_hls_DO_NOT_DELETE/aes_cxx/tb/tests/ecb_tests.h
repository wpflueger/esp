#ifndef __ECB_TESTS_H__
#define __ECB_TESTS_H__

#include "aes.h"
#include "utils.h"

/* AES Monte Carlo Test (MCT) Vectors */
/* Do multiple iterations of encryption or
   decryption (10000) while updating keys */

#define ECBMCT128_VERBOSE 0
#define ECBMCT192_VERBOSE 0
#define ECBMCT256_VERBOSE 0

/* AES Known Answer Test (KAT) Vectors */
/* Do single encryption or decryption. */

#define ECBVARTXT128_VERBOSE 0
#define ECBVARTXT192_VERBOSE 0
#define ECBVARTXT256_VERBOSE 0

#define ECBVARKEY128_VERBOSE 0
#define ECBVARKEY192_VERBOSE 0
#define ECBVARKEY256_VERBOSE 0

#define ECBGFSBOX128_VERBOSE 0
#define ECBGFSBOX192_VERBOSE 0
#define ECBGFSBOX256_VERBOSE 0

#define ECBKEYSBOX128_VERBOSE 0
#define ECBKEYSBOX192_VERBOSE 0
#define ECBKEYSBOX256_VERBOSE 0

/* AES Multiblock Message Test (MMT) Sample Vectors */

#define ECBMMT128_VERBOSE 0
#define ECBMMT192_VERBOSE 0
#define ECBMMT256_VERBOSE 0

/* Wrapper for function call */

#define AES_ECB_CIPHER(encryption, key_bytes, input_bytes, key, in, out, ret) \
    aes(ECB_OPERATION_MODE, encryption, key_bytes, 0, input_bytes, 0, 0, key, 0, in, out, 0, 0, ret)

/*****************************************************************************/

int ecb_mct128(void)
{
    unsigned i, t;
    uint8_t *buffer;
    unsigned test_passed = 0;

    cavp_data cavp;

#ifdef C_SIMULATION
    parse_cavp(&cavp, "../tests/aesmct/ECBMCT128.rsp", ECB_OPERATION_MODE);
#else // VIVADO_HLS
    parse_cavp(&cavp, "../../../../../tests/aesmct/ECBMCT128.rsp", ECB_OPERATION_MODE);
#endif // C_SIMULATION

    /* Encryption tests */

    printf("Encryption tests\n");
    for (i = 0; i < cavp.enc_tests; ++i)
    {
        uint8_t *curr_p;
        uint32_t curr_lp = cavp.lp[i];

        curr_p = (uint8_t *) malloc((sizeof(uint8_t) * curr_lp).to_uint64());
        buffer = (uint8_t *) malloc((sizeof(uint8_t) * curr_lp).to_uint64());
        memcpy(curr_p, cavp.p[i], (sizeof(uint8_t) * curr_lp).to_uint64());

        for (t = 0; t < 1000; ++t)
        {
            int ret = 0;

            AES_ECB_CIPHER(ENCRYPTION_MODE, 128 / 8, curr_lp, cavp.k[i], curr_p, buffer, ret);
            memcpy(curr_p, buffer, (sizeof(uint8_t) * curr_lp).to_uint64());
            //break;
        }

        test_passed += eval_cavp(&cavp, buffer, NULL, i, true,
			0, ECB_OPERATION_MODE, ECBMCT128_VERBOSE);

        free(buffer);
        free(curr_p);
        //break;
    }

    /* Decryption tests */

    printf("Decryption tests\n");
    for (i = cavp.enc_tests; i < cavp.tot_tests; ++i)
    {
        uint8_t *curr_c;
        uint32_t curr_lp = cavp.lp[i];

        curr_c = (uint8_t *) malloc((sizeof(uint8_t) * curr_lp).to_uint64());
        buffer = (uint8_t *) malloc((sizeof(uint8_t) * curr_lp).to_uint64());
        memcpy(curr_c, cavp.c[i], (sizeof(uint8_t) * curr_lp).to_uint64());

        for (t = 0; t < 1000; ++t)
        {
            int ret = 0;

            AES_ECB_CIPHER(DECRYPTION_MODE, 128 / 8, curr_lp, cavp.k[i], curr_c, buffer, ret);
            memcpy(curr_c, buffer, (sizeof(uint8_t) * curr_lp).to_uint64());
            //break;
        }

        test_passed += eval_cavp(&cavp, buffer, NULL, i, false,
            0, ECB_OPERATION_MODE, ECBMCT128_VERBOSE);

        free(buffer);
        free(curr_c);
        //break;
    }

    printf("Info: test passed #%u out of #%u (ECBMCT128)\n",
           test_passed, cavp.tot_tests);

    free_cavp(&cavp, ECB_OPERATION_MODE);
    return cavp.tot_tests - test_passed;
}

int ecb_mct192(void)
{
    unsigned i, t;
    uint8_t *buffer;
    unsigned test_passed = 0;

    cavp_data cavp;

#ifdef C_SIMULATION
    parse_cavp(&cavp, "../tests/aesmct/ECBMCT192.rsp", ECB_OPERATION_MODE);
#else // VIVADO_HLS
    parse_cavp(&cavp, "../../../../../tests/aesmct/ECBMCT192.rsp", ECB_OPERATION_MODE);
#endif // C_SIMULATION

    /* Encryption tests */

    for (i = 0; i < cavp.enc_tests; ++i)
    {
        uint8_t *curr_p;
        uint32_t curr_lp = cavp.lp[i];

        curr_p = (uint8_t *) malloc((sizeof(uint8_t) * curr_lp).to_uint64());
        buffer = (uint8_t *) malloc((sizeof(uint8_t) * curr_lp).to_uint64());
        memcpy(curr_p, cavp.p[i], (sizeof(uint8_t) * curr_lp).to_uint64());

        for (t = 0; t < 1000; ++t)
        {
            int ret = 0;

            AES_ECB_CIPHER(ENCRYPTION_MODE, 192 / 8, curr_lp, cavp.k[i], curr_p, buffer, ret);
            memcpy(curr_p, buffer, (sizeof(uint8_t) * curr_lp).to_uint64());
        }

        test_passed += eval_cavp(&cavp, buffer, NULL, i, true,
			0, ECB_OPERATION_MODE, ECBMCT192_VERBOSE);

        free(buffer);
        free(curr_p);
    }

    /* Decryption tests */

    for (i = cavp.enc_tests; i < cavp.tot_tests; ++i)
    {
        uint8_t *curr_c;
        uint32_t curr_lp = cavp.lp[i];

        curr_c = (uint8_t *) malloc((sizeof(uint8_t) * curr_lp).to_uint64());
        buffer = (uint8_t *) malloc((sizeof(uint8_t) * curr_lp).to_uint64());
        memcpy(curr_c, cavp.c[i], (sizeof(uint8_t) * curr_lp).to_uint64());

        for (t = 0; t < 1000; ++t)
        {
            int ret = 0;

            AES_ECB_CIPHER(DECRYPTION_MODE, 192 / 8, curr_lp, cavp.k[i], curr_c, buffer, ret);
            memcpy(curr_c, buffer, (sizeof(uint8_t) * curr_lp).to_uint64());
        }

        test_passed += eval_cavp(&cavp, buffer, NULL, i, false,
			0, ECB_OPERATION_MODE, ECBMCT192_VERBOSE);

        free(buffer);
        free(curr_c);
    }

    printf("Info: test passed #%u out of #%u (ECBMCT192)\n",
           test_passed, cavp.tot_tests);

    free_cavp(&cavp, ECB_OPERATION_MODE);
    return cavp.tot_tests - test_passed;
}

int ecb_mct256(void)
{
    unsigned i, t;
    uint8_t *buffer;
    unsigned test_passed = 0;

    cavp_data cavp;

#ifdef C_SIMULATION
    parse_cavp(&cavp, "../tests/aesmct/ECBMCT256.rsp", ECB_OPERATION_MODE);
#else // VIVADO_HLS
    parse_cavp(&cavp, "../../../../../tests/aesmct/ECBMCT256.rsp", ECB_OPERATION_MODE);
#endif // C_SIMULATION

    /* Encryption tests */

    for (i = 0; i < cavp.enc_tests; ++i)
    {
        uint8_t *curr_p;
        uint32_t curr_lp = cavp.lp[i];

        curr_p = (uint8_t *) malloc((sizeof(uint8_t) * curr_lp).to_uint64());
        buffer = (uint8_t *) malloc((sizeof(uint8_t) * curr_lp).to_uint64());
        memcpy(curr_p, cavp.p[i], (sizeof(uint8_t) * curr_lp).to_uint64());

        for (t = 0; t < 1000; ++t)
        {

            int ret = 0;

            AES_ECB_CIPHER(ENCRYPTION_MODE, 256 / 8, curr_lp, cavp.k[i], curr_p, buffer, ret);
            memcpy(curr_p, buffer, (sizeof(uint8_t) * curr_lp).to_uint64());
        }

        test_passed += eval_cavp(&cavp, buffer, NULL, i, true,
			0, ECB_OPERATION_MODE, ECBMCT256_VERBOSE);

        free(buffer);
        free(curr_p);
    }

    /* Decryption tests */

    for (i = cavp.enc_tests; i < cavp.tot_tests; ++i)
    {
        uint8_t *curr_c;
        uint32_t curr_lp = cavp.lp[i];

        curr_c = (uint8_t *) malloc((sizeof(uint8_t) * curr_lp).to_uint64());
        buffer = (uint8_t *) malloc((sizeof(uint8_t) * curr_lp).to_uint64());
        memcpy(curr_c, cavp.c[i], (sizeof(uint8_t) * curr_lp).to_uint64());

        for (t = 0; t < 1000; ++t)
        {

            int ret = 0;

            AES_ECB_CIPHER(DECRYPTION_MODE, 256 / 8, curr_lp, cavp.k[i], curr_c, buffer, ret);
            memcpy(curr_c, buffer, (sizeof(uint8_t) * curr_lp).to_uint64());
        }

        test_passed += eval_cavp(&cavp, buffer, NULL, i, false,
			0, ECB_OPERATION_MODE, ECBMCT256_VERBOSE);

        free(buffer);
        free(curr_c);
    }

    printf("Info: test passed #%u out of #%u (ECBMCT256)\n",
           test_passed, cavp.tot_tests);

    free_cavp(&cavp, ECB_OPERATION_MODE);
    return cavp.tot_tests - test_passed;
}

/*****************************************************************************/

int ecb_vartxt128(void)
{
    unsigned i;
    uint8_t *buffer;
    unsigned test_passed = 0;

    cavp_data cavp;

#ifdef C_SIMULATION
    parse_cavp(&cavp, "../tests/aeskat/ECBVarTxt128.rsp", ECB_OPERATION_MODE);
#else // VIVADO_HLS
    parse_cavp(&cavp, "../../../../../tests/aeskat/ECBVarTxt128.rsp", ECB_OPERATION_MODE);
#endif // C_SIMULATION

    /* Encryption tests */

    for (i = 0; i < cavp.enc_tests; ++i)
    {
        buffer = (uint8_t *) malloc((sizeof(uint8_t) * cavp.lc[i]).to_uint64());

        int ret = 0;

        AES_ECB_CIPHER(ENCRYPTION_MODE, 128 / 8, cavp.lc[i], cavp.k[i], cavp.p[i], buffer, ret);

        test_passed += eval_cavp(&cavp, buffer, NULL, i, true,
            0, ECB_OPERATION_MODE, ECBVARTXT128_VERBOSE);

        free(buffer);
    }

    /* Decryption tests */

    for (i = cavp.enc_tests; i < cavp.tot_tests; ++i)
    {
        buffer = (uint8_t *) malloc((sizeof(uint8_t) * cavp.lp[i]).to_uint64());

        int ret = 0;

        AES_ECB_CIPHER(DECRYPTION_MODE, 128 / 8, cavp.lp[i], cavp.k[i], cavp.c[i], buffer, ret);

        test_passed += eval_cavp(&cavp, buffer, NULL, i, false,
            0, ECB_OPERATION_MODE, ECBVARTXT128_VERBOSE);

        free(buffer);
    }

    printf("Info: test passed #%u out of #%u (ECBVarTxt128)\n",
           test_passed, cavp.tot_tests);

    free_cavp(&cavp, ECB_OPERATION_MODE);
    return cavp.tot_tests - test_passed;
}

int ecb_vartxt192(void)
{
    unsigned i;
    uint8_t *buffer;
    unsigned test_passed = 0;

    cavp_data cavp;

#ifdef C_SIMULATION
    parse_cavp(&cavp, "../tests/aeskat/ECBVarTxt192.rsp", ECB_OPERATION_MODE);
#else // VIVADO_HLS
    parse_cavp(&cavp, "../../../../../tests/aeskat/ECBVarTxt192.rsp", ECB_OPERATION_MODE);
#endif // C_SIMULATION

    /* Encryption tests */

    for (i = 0; i < cavp.enc_tests; ++i)
    {
        buffer = (uint8_t *) malloc((sizeof(uint8_t) * cavp.lc[i]).to_uint64());

        int ret = 0;

        AES_ECB_CIPHER(ENCRYPTION_MODE, 192 / 8, cavp.lc[i], cavp.k[i], cavp.p[i], buffer, ret);

        test_passed += eval_cavp(&cavp, buffer, NULL, i, true,
            0, ECB_OPERATION_MODE, ECBVARTXT192_VERBOSE);

        free(buffer);
    }

    /* Decryption tests */

    for (i = cavp.enc_tests; i < cavp.tot_tests; ++i)
    {
        buffer = (uint8_t *) malloc((sizeof(uint8_t) * cavp.lp[i]).to_uint64());

        int ret = 0;

        AES_ECB_CIPHER(DECRYPTION_MODE, 192 / 8, cavp.lp[i], cavp.k[i], cavp.c[i], buffer, ret);

        test_passed += eval_cavp(&cavp, buffer, NULL, i, false,
            0, ECB_OPERATION_MODE, ECBVARTXT192_VERBOSE);

        free(buffer);
    }

    printf("Info: test passed #%u out of #%u (ECBVarTxt192)\n",
           test_passed, cavp.tot_tests);

    free_cavp(&cavp, ECB_OPERATION_MODE);
    return cavp.tot_tests - test_passed;
}

int ecb_vartxt256(void)
{
    unsigned i;
    uint8_t *buffer;
    unsigned test_passed = 0;

    cavp_data cavp;

#ifdef C_SIMULATION
    parse_cavp(&cavp, "../tests/aeskat/ECBVarTxt256.rsp", ECB_OPERATION_MODE);
#else // VIVADO_HLS
    parse_cavp(&cavp, "../../../../../tests/aeskat/ECBVarTxt256.rsp", ECB_OPERATION_MODE);
#endif // C_SIMULATION

    /* Encryption tests */

    for (i = 0; i < cavp.enc_tests; ++i)
    {
        buffer = (uint8_t *) malloc((sizeof(uint8_t) * cavp.lc[i]).to_uint64());

        int ret = 0;

        AES_ECB_CIPHER(ENCRYPTION_MODE, 256 / 8, cavp.lc[i], cavp.k[i], cavp.p[i], buffer, ret);

        test_passed += eval_cavp(&cavp, buffer, NULL, i, true,
            0, ECB_OPERATION_MODE, ECBVARTXT256_VERBOSE);

        free(buffer);
    }

    /* Decryption tests */

    for (i = cavp.enc_tests; i < cavp.tot_tests; ++i)
    {
        buffer = (uint8_t *) malloc((sizeof(uint8_t) * cavp.lp[i]).to_uint64());

        int ret = 0;

        AES_ECB_CIPHER(DECRYPTION_MODE, 256 / 8, cavp.lp[i], cavp.k[i], cavp.c[i], buffer, ret);

        test_passed += eval_cavp(&cavp, buffer, NULL, i, false,
            0, ECB_OPERATION_MODE, ECBVARTXT256_VERBOSE);

        free(buffer);
    }

    printf("Info: test passed #%u out of #%u (ECBVarTxt256)\n",
           test_passed, cavp.tot_tests);

    free_cavp(&cavp, ECB_OPERATION_MODE);
    return cavp.tot_tests - test_passed;
}

/*****************************************************************************/

int ecb_varkey128(void)
{
    unsigned i;
    uint8_t *buffer;
    unsigned test_passed = 0;

    cavp_data cavp;

#ifdef C_SIMULATION
    parse_cavp(&cavp, "../tests/aeskat/ECBVarKey128.rsp", ECB_OPERATION_MODE);
#else // VIVADO_HLS
    parse_cavp(&cavp, "../../../../../tests/aeskat/ECBVarKey128.rsp", ECB_OPERATION_MODE);
#endif // C_SIMULATION

    /* Encryption tests */

    for (i = 0; i < cavp.enc_tests; ++i)
    {
        buffer = (uint8_t *) malloc((sizeof(uint8_t) * cavp.lc[i]).to_uint64());

        int ret = 0;

        AES_ECB_CIPHER(ENCRYPTION_MODE, 128 / 8, cavp.lc[i], cavp.k[i], cavp.p[i], buffer, ret);

        test_passed += eval_cavp(&cavp, buffer, NULL, i, true,
            0, ECB_OPERATION_MODE, ECBVARKEY128_VERBOSE);

        free(buffer);
    }

    /* Decryption tests */

    for (i = cavp.enc_tests; i < cavp.tot_tests; ++i)
    {
        buffer = (uint8_t *) malloc((sizeof(uint8_t) * cavp.lp[i]).to_uint64());

        int ret = 0;

        AES_ECB_CIPHER(DECRYPTION_MODE, 128 / 8, cavp.lp[i], cavp.k[i], cavp.c[i], buffer, ret);

        test_passed += eval_cavp(&cavp, buffer, NULL, i, false,
            0, ECB_OPERATION_MODE, ECBVARKEY128_VERBOSE);

        free(buffer);
    }

    printf("Info: test passed #%u out of #%u (ECBVarKey128)\n",
           test_passed, cavp.tot_tests);

    free_cavp(&cavp, ECB_OPERATION_MODE);
    return cavp.tot_tests - test_passed;
}

int ecb_varkey192(void)
{
    unsigned i;
    uint8_t *buffer;
    unsigned test_passed = 0;

    cavp_data cavp;

#ifdef C_SIMULATION
    parse_cavp(&cavp, "../tests/aeskat/ECBVarKey192.rsp", ECB_OPERATION_MODE);
#else // VIVADO_HLS
    parse_cavp(&cavp, "../../../../../tests/aeskat/ECBVarKey192.rsp", ECB_OPERATION_MODE);
#endif // C_SIMULATION

    /* Encryption tests */

    for (i = 0; i < cavp.enc_tests; ++i)
    {
        buffer = (uint8_t *) malloc((sizeof(uint8_t) * cavp.lc[i]).to_uint64());

        int ret = 0;

        AES_ECB_CIPHER(ENCRYPTION_MODE, 192 / 8, cavp.lc[i], cavp.k[i], cavp.p[i], buffer, ret);

        test_passed += eval_cavp(&cavp, buffer, NULL, i, true,
            0, ECB_OPERATION_MODE, ECBVARKEY192_VERBOSE);

        free(buffer);
    }

    /* Decryption tests */

    for (i = cavp.enc_tests; i < cavp.tot_tests; ++i)
    {
        buffer = (uint8_t *) malloc((sizeof(uint8_t) * cavp.lp[i]).to_uint64());

        int ret = 0;

        AES_ECB_CIPHER(DECRYPTION_MODE, 192 / 8, cavp.lp[i], cavp.k[i], cavp.c[i], buffer, ret);

        test_passed += eval_cavp(&cavp, buffer, NULL, i, false,
             0, ECB_OPERATION_MODE, ECBVARKEY192_VERBOSE);

        free(buffer);
    }

    printf("Info: test passed #%u out of #%u (ECBVarKey192)\n",
           test_passed, cavp.tot_tests);

    free_cavp(&cavp, ECB_OPERATION_MODE);
    return cavp.tot_tests - test_passed;
}

int ecb_varkey256(void)
{
    unsigned i;
    uint8_t *buffer;
    unsigned test_passed = 0;

    cavp_data cavp;

#ifdef C_SIMULATION
    parse_cavp(&cavp, "../tests/aeskat/ECBVarKey256.rsp", ECB_OPERATION_MODE);
#else // VIVADO_HLS
    parse_cavp(&cavp, "../../../../../tests/aeskat/ECBVarKey256.rsp", ECB_OPERATION_MODE);
#endif // C_SIMULATION

    /* Encryption tests */

    for (i = 0; i < cavp.enc_tests; ++i)
    {
        buffer = (uint8_t *) malloc((sizeof(uint8_t) * cavp.lc[i]).to_uint64());

        int ret = 0;

        AES_ECB_CIPHER(ENCRYPTION_MODE, 256 / 8, cavp.lc[i], cavp.k[i], cavp.p[i], buffer, ret);

        test_passed += eval_cavp(&cavp, buffer, NULL, i, true,
            0, ECB_OPERATION_MODE, ECBVARKEY256_VERBOSE);

        free(buffer);
    }

    /* Decryption tests */

    for (i = cavp.enc_tests; i < cavp.tot_tests; ++i)
    {
        buffer = (uint8_t *) malloc((sizeof(uint8_t) * cavp.lp[i]).to_uint64());

        int ret = 0;

        AES_ECB_CIPHER(DECRYPTION_MODE, 256 / 8, cavp.lp[i], cavp.k[i], cavp.c[i], buffer, ret);

        test_passed += eval_cavp(&cavp, buffer, NULL, i, false,
             0, ECB_OPERATION_MODE, ECBVARKEY256_VERBOSE);

        free(buffer);
    }

    printf("Info: test passed #%u out of #%u (ECBVarKey256)\n",
           test_passed, cavp.tot_tests);

    free_cavp(&cavp, ECB_OPERATION_MODE);
    return cavp.tot_tests - test_passed;
}

/*****************************************************************************/

int ecb_gfsbox128(void)
{
    unsigned i;
    uint8_t *buffer;
    unsigned test_passed = 0;

    cavp_data cavp;

#ifdef C_SIMULATION
    parse_cavp(&cavp, "../tests/aeskat/ECBGFSbox128.rsp", ECB_OPERATION_MODE);
#else // VIVADO_HLS
    parse_cavp(&cavp, "../../../../../tests/aeskat/ECBGFSbox128.rsp", ECB_OPERATION_MODE);
#endif // C_SIMULATION

    /* Encryption tests */

    for (i = 0; i < cavp.enc_tests; ++i)
    {
        buffer = (uint8_t *) malloc((sizeof(uint8_t) * cavp.lc[i]).to_uint64());

        int ret = 0;

        AES_ECB_CIPHER(ENCRYPTION_MODE, 128 / 8, cavp.lc[i], cavp.k[i], cavp.p[i], buffer, ret);

        test_passed += eval_cavp(&cavp, buffer, NULL, i, true,
            0, ECB_OPERATION_MODE, ECBVARKEY128_VERBOSE);

        free(buffer);
    }

    /* Decryption tests */

    for (i = cavp.enc_tests; i < cavp.tot_tests; ++i)
    {
        buffer = (uint8_t *) malloc((sizeof(uint8_t) * cavp.lp[i]).to_uint64());

        int ret = 0;

        AES_ECB_CIPHER(DECRYPTION_MODE, 128 / 8, cavp.lp[i], cavp.k[i], cavp.c[i], buffer, ret);

        test_passed += eval_cavp(&cavp, buffer, NULL, i, false,
            0, ECB_OPERATION_MODE, ECBVARKEY128_VERBOSE);

        free(buffer);
    }

    printf("Info: test passed #%u out of #%u (ECBGFSbox128)\n",
           test_passed, cavp.tot_tests);

    free_cavp(&cavp, ECB_OPERATION_MODE);
    return cavp.tot_tests - test_passed;
}

int ecb_gfsbox192(void)
{
    unsigned i;
    uint8_t *buffer;
    unsigned test_passed = 0;

    cavp_data cavp;

#ifdef C_SIMULATION
    parse_cavp(&cavp, "../tests/aeskat/ECBGFSbox192.rsp", ECB_OPERATION_MODE);
#else // VIVADO_HLS
    parse_cavp(&cavp, "../../../../../tests/aeskat/ECBGFSbox192.rsp", ECB_OPERATION_MODE);
#endif // C_SIMULATION

    /* Encryption tests */

    for (i = 0; i < cavp.enc_tests; ++i)
    {
        buffer = (uint8_t *) malloc((sizeof(uint8_t) * cavp.lc[i]).to_uint64());

        int ret = 0;

        AES_ECB_CIPHER(ENCRYPTION_MODE, 192 / 8, cavp.lc[i], cavp.k[i], cavp.p[i], buffer, ret);

        test_passed += eval_cavp(&cavp, buffer, NULL, i, true,
            0, ECB_OPERATION_MODE, ECBVARKEY192_VERBOSE);

        free(buffer);
    }

    /* Decryption tests */

    for (i = cavp.enc_tests; i < cavp.tot_tests; ++i)
    {
        buffer = (uint8_t *) malloc((sizeof(uint8_t) * cavp.lp[i]).to_uint64());

        int ret = 0;

        AES_ECB_CIPHER(DECRYPTION_MODE, 192 / 8, cavp.lp[i], cavp.k[i], cavp.c[i], buffer, ret);

        test_passed += eval_cavp(&cavp, buffer, NULL, i, false,
            0, ECB_OPERATION_MODE, ECBVARKEY192_VERBOSE);

        free(buffer);
    }

    printf("Info: test passed #%u out of #%u (ECBGFSbox192)\n",
           test_passed, cavp.tot_tests);

    free_cavp(&cavp, ECB_OPERATION_MODE);
    return cavp.tot_tests - test_passed;
}

int ecb_gfsbox256(void)
{
    unsigned i;
    uint8_t *buffer;
    unsigned test_passed = 0;

    cavp_data cavp;

#ifdef C_SIMULATION
    parse_cavp(&cavp, "../tests/aeskat/ECBGFSbox256.rsp", ECB_OPERATION_MODE);
#else // VIVADO_HLS
    parse_cavp(&cavp, "../../../../../tests/aeskat/ECBGFSbox256.rsp", ECB_OPERATION_MODE);
#endif // C_SIMULATION

    /* Encryption tests */

    for (i = 0; i < cavp.enc_tests; ++i)
    {
        buffer = (uint8_t *) malloc((sizeof(uint8_t) * cavp.lc[i]).to_uint64());

        int ret = 0;

        AES_ECB_CIPHER(ENCRYPTION_MODE, 256 / 8, cavp.lc[i], cavp.k[i], cavp.p[i], buffer, ret);

        test_passed += eval_cavp(&cavp, buffer, NULL, i, true,
            0, ECB_OPERATION_MODE, ECBVARKEY256_VERBOSE);

        free(buffer);
    }

    /* Decryption tests */

    for (i = cavp.enc_tests; i < cavp.tot_tests; ++i)
    {
        buffer = (uint8_t *) malloc((sizeof(uint8_t) * cavp.lp[i]).to_uint64());

        int ret = 0;

        AES_ECB_CIPHER(DECRYPTION_MODE, 256 / 8, cavp.lp[i], cavp.k[i], cavp.c[i], buffer, ret);

        test_passed += eval_cavp(&cavp, buffer, NULL, i, false,
            0, ECB_OPERATION_MODE, ECBVARKEY256_VERBOSE);

        free(buffer);
    }

    printf("Info: test passed #%u out of #%u (ECBGFSbox256)\n",
           test_passed, cavp.tot_tests);

    free_cavp(&cavp, ECB_OPERATION_MODE);
    return cavp.tot_tests - test_passed;
}

/*****************************************************************************/

int ecb_keysbox128(void)
{
    unsigned i;
    uint8_t *buffer;
    unsigned test_passed = 0;

    cavp_data cavp;

#ifdef C_SIMULATION
    parse_cavp(&cavp, "../tests/aeskat/ECBKeySbox128.rsp", ECB_OPERATION_MODE);
#else // VIVADO_HLS
    parse_cavp(&cavp, "../../../../../tests/aeskat/ECBKeySbox128.rsp", ECB_OPERATION_MODE);
#endif // C_SIMULATION

    /* Encryption tests */

    for (i = 0; i < cavp.enc_tests; ++i)
    {
        buffer = (uint8_t *) malloc((sizeof(uint8_t) * cavp.lc[i]).to_uint64());

        int ret = 0;

        AES_ECB_CIPHER(ENCRYPTION_MODE, 128 / 8, cavp.lc[i], cavp.k[i], cavp.p[i], buffer, ret);

        test_passed += eval_cavp(&cavp, buffer, NULL, i, true,
            0, ECB_OPERATION_MODE, ECBVARKEY128_VERBOSE);

        free(buffer);
    }

    /* Decryption tests */

    for (i = cavp.enc_tests; i < cavp.tot_tests; ++i)
    {
        buffer = (uint8_t *) malloc((sizeof(uint8_t) * cavp.lp[i]).to_uint64());

        int ret = 0;

        AES_ECB_CIPHER(DECRYPTION_MODE, 128 / 8, cavp.lp[i], cavp.k[i], cavp.c[i], buffer, ret);

        test_passed += eval_cavp(&cavp, buffer, NULL, i, false,
            0, ECB_OPERATION_MODE, ECBVARKEY128_VERBOSE);

        free(buffer);
    }

    printf("Info: test passed #%u out of #%u (ECBKeySbox128)\n",
           test_passed, cavp.tot_tests);

    free_cavp(&cavp, ECB_OPERATION_MODE);
    return cavp.tot_tests - test_passed;
}

int ecb_keysbox192(void)
{
    unsigned i;
    uint8_t *buffer;
    unsigned test_passed = 0;

    cavp_data cavp;

#ifdef C_SIMULATION
    parse_cavp(&cavp, "../tests/aeskat/ECBKeySbox192.rsp", ECB_OPERATION_MODE);
#else // VIVADO_HLS
    parse_cavp(&cavp, "../../../../../tests/aeskat/ECBKeySbox192.rsp", ECB_OPERATION_MODE);
#endif // C_SIMULATION

    /* Encryption tests */

    for (i = 0; i < cavp.enc_tests; ++i)
    {
        buffer = (uint8_t *) malloc((sizeof(uint8_t) * cavp.lc[i]).to_uint64());

        int ret = 0;

        AES_ECB_CIPHER(ENCRYPTION_MODE, 192 / 8, cavp.lc[i], cavp.k[i], cavp.p[i], buffer, ret);

        test_passed += eval_cavp(&cavp, buffer, NULL, i, true,
            0, ECB_OPERATION_MODE, ECBVARKEY192_VERBOSE);

        free(buffer);
    }

    /* Decryption tests */

    for (i = cavp.enc_tests; i < cavp.tot_tests; ++i)
    {
        buffer = (uint8_t *) malloc((sizeof(uint8_t) * cavp.lp[i]).to_uint64());

        int ret = 0;

        AES_ECB_CIPHER(DECRYPTION_MODE, 192 / 8, cavp.lp[i], cavp.k[i], cavp.c[i], buffer, ret);

        test_passed += eval_cavp(&cavp, buffer, NULL, i, false,
            0, ECB_OPERATION_MODE, ECBVARKEY192_VERBOSE);

        free(buffer);
    }

    printf("Info: test passed #%u out of #%u (ECBKeySbox192)\n",
           test_passed, cavp.tot_tests);

    free_cavp(&cavp, ECB_OPERATION_MODE);
    return cavp.tot_tests - test_passed;
}

int ecb_keysbox256(void)
{
    unsigned i;
    uint8_t *buffer;
    unsigned test_passed = 0;

    cavp_data cavp;

#ifdef C_SIMULATION
    parse_cavp(&cavp, "../tests/aeskat/ECBKeySbox256.rsp", ECB_OPERATION_MODE);
#else // VIVADO_HLS
    parse_cavp(&cavp, "../../../../../tests/aeskat/ECBKeySbox256.rsp", ECB_OPERATION_MODE);
#endif // C_SIMULATION

    /* Encryption tests */

    for (i = 0; i < cavp.enc_tests; ++i)
    {
        buffer = (uint8_t *) malloc((sizeof(uint8_t) * cavp.lc[i]).to_uint64());

        int ret = 0;

        AES_ECB_CIPHER(ENCRYPTION_MODE, 256 / 8, cavp.lc[i], cavp.k[i], cavp.p[i], buffer, ret);

        test_passed += eval_cavp(&cavp, buffer, NULL, i, true,
            0, ECB_OPERATION_MODE, ECBVARKEY256_VERBOSE);

        free(buffer);
    }

    /* Decryption tests */

    for (i = cavp.enc_tests; i < cavp.tot_tests; ++i)
    {
        buffer = (uint8_t *) malloc((sizeof(uint8_t) * cavp.lp[i]).to_uint64());

        int ret = 0;

        AES_ECB_CIPHER(DECRYPTION_MODE, 256 / 8, cavp.lp[i], cavp.k[i], cavp.c[i], buffer, ret);

        test_passed += eval_cavp(&cavp, buffer, NULL, i, false,
            0, ECB_OPERATION_MODE, ECBVARKEY256_VERBOSE);

        free(buffer);
    }

    printf("Info: test passed #%u out of #%u (ECBKeySbox256)\n",
           test_passed, cavp.tot_tests);

    free_cavp(&cavp, ECB_OPERATION_MODE);
    return cavp.tot_tests - test_passed;
}

/*****************************************************************************/

int ecb_mmt128(void)
{
    unsigned i;
    uint8_t *buffer;
    unsigned test_passed = 0;

    cavp_data cavp;

#ifdef C_SIMULATION
    parse_cavp(&cavp, "../tests/aesmmt/ECBMMT128.rsp", ECB_OPERATION_MODE);
#else // VIVADO_HLS
    parse_cavp(&cavp, "../../../../../tests/aesmmt/ECBMMT128.rsp", ECB_OPERATION_MODE);
#endif // C_SIMULATION

    /* Encryption tests */

    for (i = 0; i < cavp.enc_tests; ++i)
    {
        buffer = (uint8_t *) malloc((sizeof(uint8_t) * cavp.lc[i]).to_uint64());

        int ret = 0;

        AES_ECB_CIPHER(ENCRYPTION_MODE, 128 / 8, cavp.lc[i], cavp.k[i], cavp.p[i], buffer, ret);

        test_passed += eval_cavp(&cavp, buffer, NULL, i, true,
            0, ECB_OPERATION_MODE, ECBMMT128_VERBOSE);

        free(buffer);
    }

    /* Decryption tests */

    for (i = cavp.enc_tests; i < cavp.tot_tests; ++i)
    {
        buffer = (uint8_t *) malloc((sizeof(uint8_t) * cavp.lp[i]).to_uint64());

        int ret = 0;

        AES_ECB_CIPHER(DECRYPTION_MODE, 128 / 8, cavp.lp[i], cavp.k[i], cavp.c[i], buffer, ret);

        test_passed += eval_cavp(&cavp, buffer, NULL, i, false,
            0, ECB_OPERATION_MODE, ECBMMT128_VERBOSE);

        free(buffer);
    }

    printf("Info: test passed #%u out of #%u (ECBMMT128)\n",
           test_passed, cavp.tot_tests);

    free_cavp(&cavp, ECB_OPERATION_MODE);
    return cavp.tot_tests - test_passed;
}

int ecb_mmt192(void)
{
    unsigned i;
    uint8_t *buffer;
    unsigned test_passed = 0;

    cavp_data cavp;

#ifdef C_SIMULATION
    parse_cavp(&cavp, "../tests/aesmmt/ECBMMT192.rsp", ECB_OPERATION_MODE);
#else // VIVADO_HLS
    parse_cavp(&cavp, "../../../../../tests/aesmmt/ECBMMT192.rsp", ECB_OPERATION_MODE);
#endif // C_SIMULATION

    /* Encryption tests */

    for (i = 0; i < cavp.enc_tests; ++i)
    {
        buffer = (uint8_t *) malloc((sizeof(uint8_t) * cavp.lc[i]).to_uint64());

        int ret = 0;

        AES_ECB_CIPHER(ENCRYPTION_MODE, 192 / 8, cavp.lc[i], cavp.k[i], cavp.p[i], buffer, ret);

        test_passed += eval_cavp(&cavp, buffer, NULL, i, true,
            0, ECB_OPERATION_MODE, ECBMMT192_VERBOSE);

        free(buffer);
    }

    /* Decryption tests */

    for (i = cavp.enc_tests; i < cavp.tot_tests; ++i)
    {
        buffer = (uint8_t *) malloc((sizeof(uint8_t) * cavp.lp[i]).to_uint64());

        int ret = 0;

        AES_ECB_CIPHER(DECRYPTION_MODE, 192 / 8, cavp.lp[i], cavp.k[i], cavp.c[i], buffer, ret);

        test_passed += eval_cavp(&cavp, buffer, NULL, i, false,
            0, ECB_OPERATION_MODE, ECBMMT192_VERBOSE);

        free(buffer);
    }

    printf("Info: test passed #%u out of #%u (ECBMMT192)\n",
           test_passed, cavp.tot_tests);

    free_cavp(&cavp, ECB_OPERATION_MODE);
    return cavp.tot_tests - test_passed;
}

int ecb_mmt256(void)
{
    unsigned i;
    uint8_t *buffer;
    unsigned test_passed = 0;

    cavp_data cavp;

#ifdef C_SIMULATION
    parse_cavp(&cavp, "../tests/aesmmt/ECBMMT256.rsp", ECB_OPERATION_MODE);
#else // VIVADO_HLS
    parse_cavp(&cavp, "../../../../../tests/aesmmt/ECBMMT256.rsp", ECB_OPERATION_MODE);
#endif // C_SIMULATION

    /* Encryption tests */

    for (i = 0; i < cavp.enc_tests; ++i)
    {
        buffer = (uint8_t *) malloc((sizeof(uint8_t) * cavp.lc[i]).to_uint64());

        int ret = 0;

        AES_ECB_CIPHER(ENCRYPTION_MODE, 256 / 8, cavp.lp[i], cavp.k[i], cavp.p[i], buffer, ret);

        test_passed += eval_cavp(&cavp, buffer, NULL, i, true,
            0, ECB_OPERATION_MODE, ECBMMT256_VERBOSE);

        free(buffer);
    }

    /* Decryption tests */

    for (i = cavp.enc_tests; i < cavp.tot_tests; ++i)
    {
        buffer = (uint8_t *) malloc((sizeof(uint8_t) * cavp.lp[i]).to_uint64());

        int ret = 0;

        AES_ECB_CIPHER(DECRYPTION_MODE, 256 / 8, cavp.lc[i], cavp.k[i], cavp.c[i], buffer, ret);

        test_passed += eval_cavp(&cavp, buffer, NULL, i, false,
            0, ECB_OPERATION_MODE, ECBMMT256_VERBOSE);

        free(buffer);
    }

    printf("Info: test passed #%u out of #%u (ECBMMT256)\n",
           test_passed, cavp.tot_tests);

    free_cavp(&cavp, ECB_OPERATION_MODE);
    return cavp.tot_tests - test_passed;
}

#endif /* __ECB_TESTS_H__ */
