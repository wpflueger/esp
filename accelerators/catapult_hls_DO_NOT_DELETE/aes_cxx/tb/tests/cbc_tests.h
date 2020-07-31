#ifndef __CBC_TESTS_H__
#define __CBC_TESTS_H__

#include "aes.h"
#include "utils.h"

/* AES Monte Carlo Test (MCT) Vectors */
/* Do multiple iterations of encryption or
   decryption (10000) while updating keys */

#define CBCMCT128_VERBOSE 0
#define CBCMCT192_VERBOSE 0
#define CBCMCT256_VERBOSE 0

/* AES Known Answer Test (KAT) Vectors */
/* Do single encryption or decryption. */

#define CBCVARTXT128_VERBOSE 0
#define CBCVARTXT192_VERBOSE 0
#define CBCVARTXT256_VERBOSE 0

#define CBCVARKEY128_VERBOSE 0
#define CBCVARKEY192_VERBOSE 0
#define CBCVARKEY256_VERBOSE 0

#define CBCGFSBOX128_VERBOSE 0
#define CBCGFSBOX192_VERBOSE 0
#define CBCGFSBOX256_VERBOSE 0

#define CBCKEYSBOX128_VERBOSE 0
#define CBCKEYSBOX192_VERBOSE 0
#define CBCKEYSBOX256_VERBOSE 0

/* AES Multiblock Message Test (MMT) Sample Vectors */

#define CBCMMT128_VERBOSE 0
#define CBCMMT192_VERBOSE 0
#define CBCMMT256_VERBOSE 0

/* Wrapper for function call */

#define AES_CBC_CIPHER(encryption, key_bytes, input_bytes, key, iv, in, out, ret) \
    aes(CBC_OPERATION_MODE, encryption, key_bytes, 16, input_bytes, 0, 0, key, iv, in, out, 0, 0, ret)

/*****************************************************************************/

int cbc_mct128(void)
{
    unsigned i, t;
    uint8_t *buffer;
    unsigned test_passed = 0;

    cavp_data cavp;

#ifdef C_SIMULATION
    parse_cavp(&cavp, "../tests/aesmct/CBCMCT128.rsp", CBC_OPERATION_MODE);
#else // VIVADO_HLS
    parse_cavp(&cavp, "../../../../../tests/aesmct/CBCMCT128.rsp", CBC_OPERATION_MODE);
#endif // C_SIMULATION

    /* Encryption tests */

    for (i = 0; i < cavp.enc_tests; ++i)
    {
        uint8_t *prev_p;
        uint8_t *curr_p;
        uint32_t curr_lp = cavp.lp[i];

        prev_p = (uint8_t *) malloc((sizeof(uint8_t) * curr_lp).to_uint64());
        curr_p = (uint8_t *) malloc((sizeof(uint8_t) * curr_lp).to_uint64());
        buffer = (uint8_t *) malloc((sizeof(uint8_t) * curr_lp).to_uint64());

        int ret = 0;

        AES_CBC_CIPHER(ENCRYPTION_MODE, 128 / 8, curr_lp, cavp.k[i], cavp.i[i], cavp.p[i], buffer, ret);
        memcpy(prev_p, cavp.i[i], (sizeof(uint8_t) * curr_lp).to_uint64());
        memcpy(curr_p, buffer, (sizeof(uint8_t) * curr_lp).to_uint64());

        for (t = 0; t < 999; ++t)
        {
            int ret = 0;

            AES_CBC_CIPHER(ENCRYPTION_MODE, 128 / 8, curr_lp, cavp.k[i], prev_p, curr_p, buffer, ret);
            memcpy(prev_p, curr_p, (sizeof(uint8_t) * curr_lp).to_uint64());
            memcpy(curr_p, buffer, (sizeof(uint8_t) * curr_lp).to_uint64());
        }

        test_passed += eval_cavp(&cavp, buffer, NULL, i, true,
			0, CBC_OPERATION_MODE, CBCMCT128_VERBOSE);

        free(buffer);
        free(prev_p);
        free(curr_p);
    }

    /* Decryption tests */

    for (i = cavp.enc_tests; i < cavp.tot_tests; ++i)
    {
        uint8_t *prev_c;
        uint8_t *curr_c;
        uint8_t *curr_i;
        uint32_t curr_lc = cavp.lc[i];
        uint32_t curr_li = cavp.li[i];

        prev_c = (uint8_t *) malloc((sizeof(uint8_t) * curr_lc).to_uint64());
        curr_c = (uint8_t *) malloc((sizeof(uint8_t) * curr_lc).to_uint64());
        curr_i = (uint8_t *) malloc((sizeof(uint8_t) * curr_li).to_uint64());
        buffer = (uint8_t *) malloc((sizeof(uint8_t) * curr_lc).to_uint64());

        int ret = 0;

        AES_CBC_CIPHER(DECRYPTION_MODE, 128 / 8, curr_lc, cavp.k[i], cavp.i[i], cavp.c[i], buffer, ret);
        memcpy(prev_c, buffer, (sizeof(uint8_t) * curr_lc).to_uint64());
        memcpy(curr_c, cavp.i[i], (sizeof(uint8_t) * curr_lc).to_uint64());
        memcpy(curr_i, cavp.c[i], (sizeof(uint8_t) * curr_lc).to_uint64());

        for (t = 0; t < 999; ++t)
        {

            int ret = 0;

            AES_CBC_CIPHER(DECRYPTION_MODE, 128 / 8, curr_lc, cavp.k[i], curr_i, curr_c, buffer, ret);
            memcpy(curr_i, curr_c, (sizeof(uint8_t) * curr_lc).to_uint64());
            memcpy(curr_c, prev_c, (sizeof(uint8_t) * curr_lc).to_uint64());
            memcpy(prev_c, buffer, (sizeof(uint8_t) * curr_lc).to_uint64());
        }

        test_passed += eval_cavp(&cavp, buffer, NULL, i, false,
			0, CBC_OPERATION_MODE, CBCMCT128_VERBOSE);

        free(buffer);
        free(prev_c);
        free(curr_c);
        free(curr_i);
    }

    printf("Info: test passed #%u out of #%u (CBCMCT128)\n",
           test_passed, cavp.tot_tests);

    free_cavp(&cavp, CBC_OPERATION_MODE);
    return cavp.tot_tests - test_passed;
}

int cbc_mct192(void)
{
    unsigned i, t;
    uint8_t *buffer;
    unsigned test_passed = 0;

    cavp_data cavp;

#ifdef C_SIMULATION
    parse_cavp(&cavp, "../tests/aesmct/CBCMCT192.rsp", CBC_OPERATION_MODE);
#else // VIVADO_HLS
    parse_cavp(&cavp, "../../../../../tests/aesmct/CBCMCT192.rsp", CBC_OPERATION_MODE);
#endif // C_SIMULATION

    /* Encryption tests */

    for (i = 0; i < cavp.enc_tests; ++i)
    {
        uint8_t *prev_p;
        uint8_t *curr_p;
        uint32_t curr_lp = cavp.lp[i];

        prev_p = (uint8_t *) malloc((sizeof(uint8_t) * curr_lp).to_uint64());
        curr_p = (uint8_t *) malloc((sizeof(uint8_t) * curr_lp).to_uint64());
        buffer = (uint8_t *) malloc((sizeof(uint8_t) * curr_lp).to_uint64());

        int ret = 0;

        AES_CBC_CIPHER(ENCRYPTION_MODE, 192 / 8, curr_lp, cavp.k[i], cavp.i[i], cavp.p[i], buffer, ret);
        memcpy(prev_p, cavp.i[i], (sizeof(uint8_t) * curr_lp).to_uint64());
        memcpy(curr_p, buffer, (sizeof(uint8_t) * curr_lp).to_uint64());

        for (t = 0; t < 999; ++t)
        {
            int ret = 0;

            AES_CBC_CIPHER(ENCRYPTION_MODE, 192 / 8, curr_lp, cavp.k[i], prev_p, curr_p, buffer, ret);
            memcpy(prev_p, curr_p, (sizeof(uint8_t) * curr_lp).to_uint64());
            memcpy(curr_p, buffer, (sizeof(uint8_t) * curr_lp).to_uint64());
        }

         test_passed += eval_cavp(&cavp, buffer, NULL, i, true,
			0, CBC_OPERATION_MODE, CBCMCT192_VERBOSE);

        free(buffer);
        free(prev_p);
        free(curr_p);
    }

    /* Decryption tests */

    for (i = cavp.enc_tests; i < cavp.tot_tests; ++i)
    {
        uint8_t *prev_c;
        uint8_t *curr_c;
        uint8_t *curr_i;
        uint32_t curr_lc = cavp.lc[i];
        uint32_t curr_li = cavp.li[i];

        prev_c = (uint8_t *) malloc((sizeof(uint8_t) * curr_lc).to_uint64());
        curr_c = (uint8_t *) malloc((sizeof(uint8_t) * curr_lc).to_uint64());
        curr_i = (uint8_t *) malloc((sizeof(uint8_t) * curr_li).to_uint64());
        buffer = (uint8_t *) malloc((sizeof(uint8_t) * curr_lc).to_uint64());

        int ret = 0;

        AES_CBC_CIPHER(DECRYPTION_MODE, 192 / 8, curr_lc, cavp.k[i], cavp.i[i], cavp.c[i], buffer, ret);
        memcpy(prev_c, buffer, (sizeof(uint8_t) * curr_lc).to_uint64());
        memcpy(curr_c, cavp.i[i], (sizeof(uint8_t) * curr_lc).to_uint64());
        memcpy(curr_i, cavp.c[i], (sizeof(uint8_t) * curr_lc).to_uint64());

        for (t = 0; t < 999; ++t)
        {
            int ret = 0;

            AES_CBC_CIPHER(DECRYPTION_MODE, 192 / 8, curr_lc, cavp.k[i], curr_i, curr_c, buffer, ret);
            memcpy(curr_i, curr_c, (sizeof(uint8_t) * curr_lc).to_uint64());
            memcpy(curr_c, prev_c, (sizeof(uint8_t) * curr_lc).to_uint64());
            memcpy(prev_c, buffer, (sizeof(uint8_t) * curr_lc).to_uint64());
        }

        test_passed += eval_cavp(&cavp, buffer, NULL, i, false,
			0, CBC_OPERATION_MODE, CBCMCT192_VERBOSE);

        free(buffer);
        free(prev_c);
        free(curr_c);
        free(curr_i);
    }

    printf("Info: test passed #%u out of #%u (CBCMCT192)\n",
           test_passed, cavp.tot_tests);

    free_cavp(&cavp, CBC_OPERATION_MODE);
    return cavp.tot_tests - test_passed;
}

int cbc_mct256(void)
{
    unsigned i, t;
    uint8_t *buffer;
    unsigned test_passed = 0;

    cavp_data cavp;

#ifdef C_SIMULATION
    parse_cavp(&cavp, "../tests/aesmct/CBCMCT256.rsp", CBC_OPERATION_MODE);
#else // VIVADO_HLS
    parse_cavp(&cavp, "../../../../../tests/aesmct/CBCMCT256.rsp", CBC_OPERATION_MODE);
#endif // C_SIMULATION

    /* Encryption tests */

    for (i = 0; i < cavp.enc_tests; ++i)
    {
        uint8_t *prev_p;
        uint8_t *curr_p;
        uint32_t curr_lp = cavp.lp[i];

        prev_p = (uint8_t *) malloc((sizeof(uint8_t) * curr_lp).to_uint64());
        curr_p = (uint8_t *) malloc((sizeof(uint8_t) * curr_lp).to_uint64());
        buffer = (uint8_t *) malloc((sizeof(uint8_t) * curr_lp).to_uint64());

        int ret = 0;

        AES_CBC_CIPHER(ENCRYPTION_MODE, 256 / 8, curr_lp, cavp.k[i], cavp.i[i], cavp.p[i], buffer, ret);
        memcpy(prev_p, cavp.i[i], (sizeof(uint8_t) * curr_lp).to_uint64());
        memcpy(curr_p, buffer, (sizeof(uint8_t) * curr_lp).to_uint64());

        for (t = 0; t < 999; ++t)
        {
            int ret = 0;

            AES_CBC_CIPHER(ENCRYPTION_MODE, 256 / 8, curr_lp, cavp.k[i], prev_p, curr_p, buffer, ret);
            memcpy(prev_p, curr_p, (sizeof(uint8_t) * curr_lp).to_uint64());
            memcpy(curr_p, buffer, (sizeof(uint8_t) * curr_lp).to_uint64());
        }

         test_passed += eval_cavp(&cavp, buffer, NULL, i, true,
			0, CBC_OPERATION_MODE, CBCMCT256_VERBOSE);

        free(buffer);
        free(prev_p);
        free(curr_p);
    }

    /* Decryption tests */

    for (i = cavp.enc_tests; i < cavp.tot_tests; ++i)
    {
        uint8_t *prev_c;
        uint8_t *curr_c;
        uint8_t *curr_i;
        uint32_t curr_lc = cavp.lc[i];
        uint32_t curr_li = cavp.li[i];

        prev_c = (uint8_t *) malloc((sizeof(uint8_t) * curr_lc).to_uint64());
        curr_c = (uint8_t *) malloc((sizeof(uint8_t) * curr_lc).to_uint64());
        curr_i = (uint8_t *) malloc((sizeof(uint8_t) * curr_li).to_uint64());
        buffer = (uint8_t *) malloc((sizeof(uint8_t) * curr_lc).to_uint64());

        int ret = 0;

        AES_CBC_CIPHER(DECRYPTION_MODE, 256 / 8, curr_lc, cavp.k[i], cavp.i[i], cavp.c[i], buffer, ret);
        memcpy(prev_c, buffer, (sizeof(uint8_t) * curr_lc).to_uint64());
        memcpy(curr_c, cavp.i[i], (sizeof(uint8_t) * curr_lc).to_uint64());
        memcpy(curr_i, cavp.c[i], (sizeof(uint8_t) * curr_lc).to_uint64());

        for (t = 0; t < 999; ++t)
        {
            int ret = 0;

            AES_CBC_CIPHER(DECRYPTION_MODE, 256 / 8, curr_lc, cavp.k[i], curr_i, curr_c, buffer, ret);
            memcpy(curr_i, curr_c, (sizeof(uint8_t) * curr_lc).to_uint64());
            memcpy(curr_c, prev_c, (sizeof(uint8_t) * curr_lc).to_uint64());
            memcpy(prev_c, buffer, (sizeof(uint8_t) * curr_lc).to_uint64());
        }

        test_passed += eval_cavp(&cavp, buffer, NULL, i, false,
			0, CBC_OPERATION_MODE, CBCMCT256_VERBOSE);

        free(buffer);
        free(prev_c);
        free(curr_c);
        free(curr_i);
    }



    printf("Info: test passed #%u out of #%u (CBCMCT256)\n",
           test_passed, cavp.tot_tests);

    free_cavp(&cavp, CBC_OPERATION_MODE);
    return cavp.tot_tests - test_passed;
}

/*****************************************************************************/

int cbc_vartxt128(void)
{
    unsigned i;
    uint8_t *buffer;
    unsigned test_passed = 0;

    cavp_data cavp;

#ifdef C_SIMULATION
    parse_cavp(&cavp, "../tests/aeskat/CBCVarTxt128.rsp", CBC_OPERATION_MODE);
#else // VIVADO_HLS
    parse_cavp(&cavp, "../../../../../tests/aeskat/CBCVarTxt128.rsp", CBC_OPERATION_MODE);
#endif // C_SIMULATION

    /* Encryption tests */

    for (i = 0; i < cavp.enc_tests; ++i)
    {
        buffer = (uint8_t *) malloc((sizeof(uint8_t) * cavp.lc[i]).to_uint64());

        int ret = 0;

        AES_CBC_CIPHER(ENCRYPTION_MODE, 128 / 8, cavp.lc[i], cavp.k[i], cavp.i[i], cavp.p[i], buffer, ret);

        test_passed += eval_cavp(&cavp, buffer, NULL, i, true,
            0, CBC_OPERATION_MODE, CBCVARTXT128_VERBOSE);

        free(buffer);
    }

    /* Decryption tests */

    for (i = cavp.enc_tests; i < cavp.tot_tests; ++i)
    {
        buffer = (uint8_t *) malloc((sizeof(uint8_t) * cavp.lp[i]).to_uint64());

        int ret = 0;

        AES_CBC_CIPHER(DECRYPTION_MODE, 128 / 8, cavp.lp[i], cavp.k[i], cavp.i[i], cavp.c[i], buffer, ret);

        test_passed += eval_cavp(&cavp, buffer, NULL, i, false,
            0, CBC_OPERATION_MODE, CBCVARTXT128_VERBOSE);

        free(buffer);
    }

    printf("Info: test passed #%u out of #%u (CBCVarTxt128)\n",
           test_passed, cavp.tot_tests);

    free_cavp(&cavp, CBC_OPERATION_MODE);
    return cavp.tot_tests - test_passed;
}

int cbc_vartxt192(void)
{
    unsigned i;
    uint8_t *buffer;
    unsigned test_passed = 0;

    cavp_data cavp;

#ifdef C_SIMULATION
    parse_cavp(&cavp, "../tests/aeskat/CBCVarTxt192.rsp", CBC_OPERATION_MODE);
#else // VIVADO_HLS
    parse_cavp(&cavp, "../../../../../tests/aeskat/CBCVarTxt192.rsp", CBC_OPERATION_MODE);
#endif // C_SIMULATION

    /* Encryption tests */

    for (i = 0; i < cavp.enc_tests; ++i)
    {
        buffer = (uint8_t *) malloc((sizeof(uint8_t) * cavp.lc[i]).to_uint64());

        int ret = 0;

        AES_CBC_CIPHER(ENCRYPTION_MODE, 192 / 8, cavp.lc[i], cavp.k[i], cavp.i[i], cavp.p[i], buffer, ret);

        test_passed += eval_cavp(&cavp, buffer, NULL, i, true,
            0, CBC_OPERATION_MODE, CBCVARTXT192_VERBOSE);

        free(buffer);
    }

    /* Decryption tests */

    for (i = cavp.enc_tests; i < cavp.tot_tests; ++i)
    {
        buffer = (uint8_t *) malloc((sizeof(uint8_t) * cavp.lp[i]).to_uint64());

        int ret = 0;

        AES_CBC_CIPHER(DECRYPTION_MODE, 192 / 8, cavp.lp[i], cavp.k[i], cavp.i[i], cavp.c[i], buffer, ret);

        test_passed += eval_cavp(&cavp, buffer, NULL, i, false,
            0, CBC_OPERATION_MODE, CBCVARTXT192_VERBOSE);

        free(buffer);
    }

    printf("Info: test passed #%u out of #%u (CBCVarTxt192)\n",
           test_passed, cavp.tot_tests);

    free_cavp(&cavp, CBC_OPERATION_MODE);
    return cavp.tot_tests - test_passed;
}

int cbc_vartxt256(void)
{
    unsigned i;
    uint8_t *buffer;
    unsigned test_passed = 0;

    cavp_data cavp;

#ifdef C_SIMULATION
    parse_cavp(&cavp, "../tests/aeskat/CBCVarTxt256.rsp", CBC_OPERATION_MODE);
#else // VIVADO_HLS
    parse_cavp(&cavp, "../../../../../tests/aeskat/CBCVarTxt256.rsp", CBC_OPERATION_MODE);
#endif // C_SIMULATION

    /* Encryption tests */

    for (i = 0; i < cavp.enc_tests; ++i)
    {
        buffer = (uint8_t *) malloc((sizeof(uint8_t) * cavp.lc[i]).to_uint64());

        int ret = 0;

        AES_CBC_CIPHER(ENCRYPTION_MODE, 256 / 8, cavp.lc[i], cavp.k[i], cavp.i[i], cavp.p[i], buffer, ret);

        test_passed += eval_cavp(&cavp, buffer, NULL, i, true,
            0, CBC_OPERATION_MODE, CBCVARTXT256_VERBOSE);

        free(buffer);
    }

    /* Decryption tests */

    for (i = cavp.enc_tests; i < cavp.tot_tests; ++i)
    {
        buffer = (uint8_t *) malloc((sizeof(uint8_t) * cavp.lp[i]).to_uint64());

        int ret = 0;

        AES_CBC_CIPHER(DECRYPTION_MODE, 256 / 8, cavp.lp[i], cavp.k[i], cavp.i[i], cavp.c[i], buffer, ret);

        test_passed += eval_cavp(&cavp, buffer, NULL, i, false,
            0, CBC_OPERATION_MODE, CBCVARTXT256_VERBOSE);

        free(buffer);
    }

    printf("Info: test passed #%u out of #%u (CBCVarTxt256)\n",
           test_passed, cavp.tot_tests);

    free_cavp(&cavp, CBC_OPERATION_MODE);
    return cavp.tot_tests - test_passed;
}

/*****************************************************************************/

int cbc_varkey128(void)
{
    unsigned i;
    uint8_t *buffer;
    unsigned test_passed = 0;

    cavp_data cavp;

#ifdef C_SIMULATION
    parse_cavp(&cavp, "../tests/aeskat/CBCVarKey128.rsp", CBC_OPERATION_MODE);
#else // VIVADO_HLS
    parse_cavp(&cavp, "../../../../../tests/aeskat/CBCVarKey128.rsp", CBC_OPERATION_MODE);
#endif // C_SIMULATION

    /* Encryption tests */

    for (i = 0; i < cavp.enc_tests; ++i)
    {
        buffer = (uint8_t *) malloc((sizeof(uint8_t) * cavp.lc[i]).to_uint64());

        int ret = 0;

        AES_CBC_CIPHER(ENCRYPTION_MODE, 128 / 8, cavp.lc[i], cavp.k[i], cavp.i[i], cavp.p[i], buffer, ret);

        test_passed += eval_cavp(&cavp, buffer, NULL, i, true,
            0, CBC_OPERATION_MODE, CBCVARKEY128_VERBOSE);

        free(buffer);
    }

    /* Decryption tests */

    for (i = cavp.enc_tests; i < cavp.tot_tests; ++i)
    {
        buffer = (uint8_t *) malloc((sizeof(uint8_t) * cavp.lp[i]).to_uint64());

        int ret = 0;

        AES_CBC_CIPHER(DECRYPTION_MODE, 128 / 8, cavp.lp[i], cavp.k[i], cavp.i[i], cavp.c[i], buffer, ret);

        test_passed += eval_cavp(&cavp, buffer, NULL, i, false,
            0, CBC_OPERATION_MODE, CBCVARKEY128_VERBOSE);

        free(buffer);
    }

    printf("Info: test passed #%u out of #%u (CBCVarKey128)\n",
           test_passed, cavp.tot_tests);

    free_cavp(&cavp, CBC_OPERATION_MODE);
    return cavp.tot_tests - test_passed;
}

int cbc_varkey192(void)
{
    unsigned i;
    uint8_t *buffer;
    unsigned test_passed = 0;

    cavp_data cavp;

#ifdef C_SIMULATION
    parse_cavp(&cavp, "../tests/aeskat/CBCVarKey192.rsp", CBC_OPERATION_MODE);
#else // VIVADO_HLS
    parse_cavp(&cavp, "../../../../../tests/aeskat/CBCVarKey192.rsp", CBC_OPERATION_MODE);
#endif // C_SIMULATION

    /* Encryption tests */

    for (i = 0; i < cavp.enc_tests; ++i)
    {
        buffer = (uint8_t *) malloc((sizeof(uint8_t) * cavp.lc[i]).to_uint64());

        int ret = 0;

        AES_CBC_CIPHER(ENCRYPTION_MODE, 192 / 8, cavp.lc[i], cavp.k[i], cavp.i[i], cavp.p[i], buffer, ret);

        test_passed += eval_cavp(&cavp, buffer, NULL, i, true,
            0, CBC_OPERATION_MODE, CBCVARKEY192_VERBOSE);

        free(buffer);
    }

    /* Decryption tests */

    for (i = cavp.enc_tests; i < cavp.tot_tests; ++i)
    {
        buffer = (uint8_t *) malloc((sizeof(uint8_t) * cavp.lp[i]).to_uint64());

        int ret = 0;

        AES_CBC_CIPHER(DECRYPTION_MODE, 192 / 8, cavp.lp[i], cavp.k[i], cavp.i[i], cavp.c[i], buffer, ret);

        test_passed += eval_cavp(&cavp, buffer, NULL, i, false,
             0, CBC_OPERATION_MODE, CBCVARKEY192_VERBOSE);

        free(buffer);
    }

    printf("Info: test passed #%u out of #%u (CBCVarKey192)\n",
           test_passed, cavp.tot_tests);

    free_cavp(&cavp, CBC_OPERATION_MODE);
    return cavp.tot_tests - test_passed;
}

int cbc_varkey256(void)
{
    unsigned i;
    uint8_t *buffer;
    unsigned test_passed = 0;

    cavp_data cavp;

#ifdef C_SIMULATION
    parse_cavp(&cavp, "../tests/aeskat/CBCVarKey256.rsp", CBC_OPERATION_MODE);
#else // VIVADO_HLS
    parse_cavp(&cavp, "../../../../../tests/aeskat/CBCVarKey256.rsp", CBC_OPERATION_MODE);
#endif // C_SIMULATION

    /* Encryption tests */

    for (i = 0; i < cavp.enc_tests; ++i)
    {
        buffer = (uint8_t *) malloc((sizeof(uint8_t) * cavp.lc[i]).to_uint64());

        int ret = 0;

        AES_CBC_CIPHER(ENCRYPTION_MODE, 256 / 8, cavp.lc[i], cavp.k[i], cavp.i[i], cavp.p[i], buffer, ret);

        test_passed += eval_cavp(&cavp, buffer, NULL, i, true,
            0, CBC_OPERATION_MODE, CBCVARKEY256_VERBOSE);

        free(buffer);
    }

    /* Decryption tests */

    for (i = cavp.enc_tests; i < cavp.tot_tests; ++i)
    {
        buffer = (uint8_t *) malloc((sizeof(uint8_t) * cavp.lp[i]).to_uint64());

        int ret = 0;

        AES_CBC_CIPHER(DECRYPTION_MODE, 256 / 8, cavp.lp[i], cavp.k[i], cavp.i[i], cavp.c[i], buffer, ret);

        test_passed += eval_cavp(&cavp, buffer, NULL, i, false,
             0, CBC_OPERATION_MODE, CBCVARKEY256_VERBOSE);

        free(buffer);
    }

    printf("Info: test passed #%u out of #%u (CBCVarKey256)\n",
           test_passed, cavp.tot_tests);

    free_cavp(&cavp, CBC_OPERATION_MODE);
    return cavp.tot_tests - test_passed;
}

/*****************************************************************************/

int cbc_gfsbox128(void)
{
    unsigned i;
    uint8_t *buffer;
    unsigned test_passed = 0;

    cavp_data cavp;

#ifdef C_SIMULATION
    parse_cavp(&cavp, "../tests/aeskat/CBCGFSbox128.rsp", CBC_OPERATION_MODE);
#else // VIVADO_HLS
    parse_cavp(&cavp, "../../../../../tests/aeskat/CBCGFSbox128.rsp", CBC_OPERATION_MODE);
#endif // C_SIMULATION

    /* Encryption tests */

    for (i = 0; i < cavp.enc_tests; ++i)
    {
        buffer = (uint8_t *) malloc((sizeof(uint8_t) * cavp.lc[i]).to_uint64());

        int ret = 0;

        AES_CBC_CIPHER(ENCRYPTION_MODE, 128 / 8, cavp.lc[i], cavp.k[i], cavp.i[i], cavp.p[i], buffer, ret);

        test_passed += eval_cavp(&cavp, buffer, NULL, i, true,
            0, CBC_OPERATION_MODE, CBCVARKEY128_VERBOSE);

        free(buffer);
    }

    /* Decryption tests */

    for (i = cavp.enc_tests; i < cavp.tot_tests; ++i)
    {
        buffer = (uint8_t *) malloc((sizeof(uint8_t) * cavp.lp[i]).to_uint64());

        int ret = 0;

        AES_CBC_CIPHER(DECRYPTION_MODE, 128 / 8, cavp.lp[i], cavp.k[i], cavp.i[i], cavp.c[i], buffer, ret);

        test_passed += eval_cavp(&cavp, buffer, NULL, i, false,
            0, CBC_OPERATION_MODE, CBCVARKEY128_VERBOSE);

        free(buffer);
    }

    printf("Info: test passed #%u out of #%u (CBCGFSbox128)\n",
           test_passed, cavp.tot_tests);

    free_cavp(&cavp, CBC_OPERATION_MODE);
    return cavp.tot_tests - test_passed;
}

int cbc_gfsbox192(void)
{
    unsigned i;
    uint8_t *buffer;
    unsigned test_passed = 0;

    cavp_data cavp;

#ifdef C_SIMULATION
    parse_cavp(&cavp, "../tests/aeskat/CBCGFSbox192.rsp", CBC_OPERATION_MODE);
#else // VIVADO_HLS
    parse_cavp(&cavp, "../../../../../tests/aeskat/CBCGFSbox192.rsp", CBC_OPERATION_MODE);
#endif // C_SIMULATION

    /* Encryption tests */

    for (i = 0; i < cavp.enc_tests; ++i)
    {
        buffer = (uint8_t *) malloc((sizeof(uint8_t) * cavp.lc[i]).to_uint64());

        int ret = 0;

        AES_CBC_CIPHER(ENCRYPTION_MODE, 192 / 8, cavp.lc[i], cavp.k[i], cavp.i[i], cavp.p[i], buffer, ret);

        test_passed += eval_cavp(&cavp, buffer, NULL, i, true,
            0, CBC_OPERATION_MODE, CBCVARKEY192_VERBOSE);

        free(buffer);
    }

    /* Decryption tests */

    for (i = cavp.enc_tests; i < cavp.tot_tests; ++i)
    {
        buffer = (uint8_t *) malloc((sizeof(uint8_t) * cavp.lp[i]).to_uint64());

        int ret = 0;

        AES_CBC_CIPHER(DECRYPTION_MODE, 192 / 8, cavp.lp[i], cavp.k[i], cavp.i[i], cavp.c[i], buffer, ret);

        test_passed += eval_cavp(&cavp, buffer, NULL, i, false,
            0, CBC_OPERATION_MODE, CBCVARKEY192_VERBOSE);

        free(buffer);
    }

    printf("Info: test passed #%u out of #%u (CBCGFSbox192)\n",
           test_passed, cavp.tot_tests);

    free_cavp(&cavp, CBC_OPERATION_MODE);
    return cavp.tot_tests - test_passed;
}

int cbc_gfsbox256(void)
{
    unsigned i;
    uint8_t *buffer;
    unsigned test_passed = 0;

    cavp_data cavp;

#ifdef C_SIMULATION
    parse_cavp(&cavp, "../tests/aeskat/CBCGFSbox256.rsp", CBC_OPERATION_MODE);
#else // VIVADO_HLS
    parse_cavp(&cavp, "../../../../../tests/aeskat/CBCGFSbox256.rsp", CBC_OPERATION_MODE);
#endif // C_SIMULATION

    /* Encryption tests */

    for (i = 0; i < cavp.enc_tests; ++i)
    {
        buffer = (uint8_t *) malloc((sizeof(uint8_t) * cavp.lc[i]).to_uint64());

        int ret = 0;

        AES_CBC_CIPHER(ENCRYPTION_MODE, 256 / 8, cavp.lc[i], cavp.k[i], cavp.i[i], cavp.p[i], buffer, ret);

        test_passed += eval_cavp(&cavp, buffer, NULL, i, true,
            0, CBC_OPERATION_MODE, CBCVARKEY256_VERBOSE);

        free(buffer);
    }

    /* Decryption tests */

    for (i = cavp.enc_tests; i < cavp.tot_tests; ++i)
    {
        buffer = (uint8_t *) malloc((sizeof(uint8_t) * cavp.lp[i]).to_uint64());

        int ret = 0;

        AES_CBC_CIPHER(DECRYPTION_MODE, 256 / 8, cavp.lp[i], cavp.k[i], cavp.i[i], cavp.c[i], buffer, ret);

        test_passed += eval_cavp(&cavp, buffer, NULL, i, false,
            0, CBC_OPERATION_MODE, CBCVARKEY256_VERBOSE);

        free(buffer);
    }

    printf("Info: test passed #%u out of #%u (CBCGFSbox256)\n",
           test_passed, cavp.tot_tests);

    free_cavp(&cavp, CBC_OPERATION_MODE);
    return cavp.tot_tests - test_passed;
}

/*****************************************************************************/

int cbc_keysbox128(void)
{
    unsigned i;
    uint8_t *buffer;
    unsigned test_passed = 0;

    cavp_data cavp;

#ifdef C_SIMULATION
    parse_cavp(&cavp, "../tests/aeskat/CBCKeySbox128.rsp", CBC_OPERATION_MODE);
#else // VIVADO_HLS
    parse_cavp(&cavp, "../../../../../tests/aeskat/CBCKeySbox128.rsp", CBC_OPERATION_MODE);
#endif // C_SIMULATION

    /* Encryption tests */

    for (i = 0; i < cavp.enc_tests; ++i)
    {
        buffer = (uint8_t *) malloc((sizeof(uint8_t) * cavp.lc[i]).to_uint64());

        int ret = 0;

        AES_CBC_CIPHER(ENCRYPTION_MODE, 128 / 8, cavp.lc[i], cavp.k[i], cavp.i[i], cavp.p[i], buffer, ret);

        test_passed += eval_cavp(&cavp, buffer, NULL, i, true,
            0, CBC_OPERATION_MODE, CBCVARKEY128_VERBOSE);

        free(buffer);
    }

    /* Decryption tests */

    for (i = cavp.enc_tests; i < cavp.tot_tests; ++i)
    {
        buffer = (uint8_t *) malloc((sizeof(uint8_t) * cavp.lp[i]).to_uint64());

        int ret = 0;

        AES_CBC_CIPHER(DECRYPTION_MODE, 128 / 8, cavp.lp[i], cavp.k[i], cavp.i[i], cavp.c[i], buffer, ret);

        test_passed += eval_cavp(&cavp, buffer, NULL, i, false,
            0, CBC_OPERATION_MODE, CBCVARKEY128_VERBOSE);

        free(buffer);
    }

    printf("Info: test passed #%u out of #%u (CBCKeySbox128)\n",
           test_passed, cavp.tot_tests);

    free_cavp(&cavp, CBC_OPERATION_MODE);
    return cavp.tot_tests - test_passed;
}

int cbc_keysbox192(void)
{
    unsigned i;
    uint8_t *buffer;
    unsigned test_passed = 0;

    cavp_data cavp;

#ifdef C_SIMULATION
    parse_cavp(&cavp, "../tests/aeskat/CBCKeySbox192.rsp", CBC_OPERATION_MODE);
#else // VIVADO_HLS
    parse_cavp(&cavp, "../../../../../tests/aeskat/CBCKeySbox192.rsp", CBC_OPERATION_MODE);
#endif // C_SIMULATION

    /* Encryption tests */

    for (i = 0; i < cavp.enc_tests; ++i)
    {
        buffer = (uint8_t *) malloc((sizeof(uint8_t) * cavp.lc[i]).to_uint64());

        int ret = 0;

        AES_CBC_CIPHER(ENCRYPTION_MODE, 192 / 8, cavp.lc[i], cavp.k[i], cavp.i[i], cavp.p[i], buffer, ret);

        test_passed += eval_cavp(&cavp, buffer, NULL, i, true,
            0, CBC_OPERATION_MODE, CBCVARKEY192_VERBOSE);

        free(buffer);
    }

    /* Decryption tests */

    for (i = cavp.enc_tests; i < cavp.tot_tests; ++i)
    {
        buffer = (uint8_t *) malloc((sizeof(uint8_t) * cavp.lp[i]).to_uint64());

        int ret = 0;

        AES_CBC_CIPHER(DECRYPTION_MODE, 192 / 8, cavp.lp[i], cavp.k[i], cavp.i[i], cavp.c[i], buffer, ret);

        test_passed += eval_cavp(&cavp, buffer, NULL, i, false,
            0, CBC_OPERATION_MODE, CBCVARKEY192_VERBOSE);

        free(buffer);
    }

    printf("Info: test passed #%u out of #%u (CBCKeySbox192)\n",
           test_passed, cavp.tot_tests);

    free_cavp(&cavp, CBC_OPERATION_MODE);
    return cavp.tot_tests - test_passed;
}

int cbc_keysbox256(void)
{
    unsigned i;
    uint8_t *buffer;
    unsigned test_passed = 0;

    cavp_data cavp;

#ifdef C_SIMULATION
    parse_cavp(&cavp, "../tests/aeskat/CBCKeySbox256.rsp", CBC_OPERATION_MODE);
#else // VIVADO_HLS
    parse_cavp(&cavp, "../../../../../tests/aeskat/CBCKeySbox256.rsp", CBC_OPERATION_MODE);
#endif // C_SIMULATION

    /* Encryption tests */

    for (i = 0; i < cavp.enc_tests; ++i)
    {
        buffer = (uint8_t *) malloc((sizeof(uint8_t) * cavp.lc[i]).to_uint64());

        int ret = 0;

        AES_CBC_CIPHER(ENCRYPTION_MODE, 256 / 8, cavp.lc[i], cavp.k[i], cavp.i[i], cavp.p[i], buffer, ret);

        test_passed += eval_cavp(&cavp, buffer, NULL, i, true,
            0, CBC_OPERATION_MODE, CBCVARKEY256_VERBOSE);

        free(buffer);
    }

    /* Decryption tests */

    for (i = cavp.enc_tests; i < cavp.tot_tests; ++i)
    {
        buffer = (uint8_t *) malloc((sizeof(uint8_t) * cavp.lp[i]).to_uint64());

        int ret = 0;

        AES_CBC_CIPHER(DECRYPTION_MODE, 256 / 8, cavp.lp[i], cavp.k[i], cavp.i[i], cavp.c[i], buffer, ret);

        test_passed += eval_cavp(&cavp, buffer, NULL, i, false,
            0, CBC_OPERATION_MODE, CBCVARKEY256_VERBOSE);

        free(buffer);
    }

    printf("Info: test passed #%u out of #%u (CBCKeySbox256)\n",
           test_passed, cavp.tot_tests);

    free_cavp(&cavp, CBC_OPERATION_MODE);
    return cavp.tot_tests - test_passed;
}

/*****************************************************************************/

int cbc_mmt128(void)
{
    unsigned i;
    uint8_t *buffer;
    unsigned test_passed = 0;

    cavp_data cavp;

#ifdef C_SIMULATION
    parse_cavp(&cavp, "../tests/aesmmt/CBCMMT128.rsp", CBC_OPERATION_MODE);
#else // VIVADO_HLS
    parse_cavp(&cavp, "../../../../../tests/aesmmt/CBCMMT128.rsp", CBC_OPERATION_MODE);
#endif // C_SIMULATION

    /* Encryption tests */

    for (i = 0; i < cavp.enc_tests; ++i)
    {
        buffer = (uint8_t *) malloc((sizeof(uint8_t) * cavp.lc[i]).to_uint64());

        int ret = 0;

        AES_CBC_CIPHER(ENCRYPTION_MODE, 128 / 8, cavp.lc[i], cavp.k[i], cavp.i[i], cavp.p[i], buffer, ret);

        test_passed += eval_cavp(&cavp, buffer, NULL, i, true,
            0, CBC_OPERATION_MODE, CBCMMT128_VERBOSE);

        free(buffer);
    }

    /* Decryption tests */

    for (i = cavp.enc_tests; i < cavp.tot_tests; ++i)
    {
        buffer = (uint8_t *) malloc((sizeof(uint8_t) * cavp.lp[i]).to_uint64());

        int ret = 0;

        AES_CBC_CIPHER(DECRYPTION_MODE, 128 / 8, cavp.lp[i], cavp.k[i], cavp.i[i], cavp.c[i], buffer, ret);

        test_passed += eval_cavp(&cavp, buffer, NULL, i, false,
            0, CBC_OPERATION_MODE, CBCMMT128_VERBOSE);

        free(buffer);
    }

    printf("Info: test passed #%u out of #%u (CBCMMT128)\n",
           test_passed, cavp.tot_tests);

    free_cavp(&cavp, CBC_OPERATION_MODE);
    return cavp.tot_tests - test_passed;
}

int cbc_mmt192(void)
{
    unsigned i;
    uint8_t *buffer;
    unsigned test_passed = 0;

    cavp_data cavp;

#ifdef C_SIMULATION
    parse_cavp(&cavp, "../tests/aesmmt/CBCMMT192.rsp", CBC_OPERATION_MODE);
#else // VIVADO_HLS
    parse_cavp(&cavp, "../../../../../tests/aesmmt/CBCMMT192.rsp", CBC_OPERATION_MODE);
#endif // C_SIMULATION

    /* Encryption tests */

    for (i = 0; i < cavp.enc_tests; ++i)
    {
        buffer = (uint8_t *) malloc((sizeof(uint8_t) * cavp.lc[i]).to_uint64());

        int ret = 0;

        AES_CBC_CIPHER(ENCRYPTION_MODE, 192 / 8, cavp.lc[i], cavp.k[i], cavp.i[i], cavp.p[i], buffer, ret);

        test_passed += eval_cavp(&cavp, buffer, NULL, i, true,
            0, CBC_OPERATION_MODE, CBCMMT192_VERBOSE);

        free(buffer);
    }

    /* Decryption tests */

    for (i = cavp.enc_tests; i < cavp.tot_tests; ++i)
    {
        buffer = (uint8_t *) malloc((sizeof(uint8_t) * cavp.lp[i]).to_uint64());

        int ret = 0;

        AES_CBC_CIPHER(DECRYPTION_MODE, 192 / 8, cavp.lp[i], cavp.k[i], cavp.i[i], cavp.c[i], buffer, ret);

        test_passed += eval_cavp(&cavp, buffer, NULL, i, false,
            0, CBC_OPERATION_MODE, CBCMMT192_VERBOSE);

        free(buffer);
    }

    printf("Info: test passed #%u out of #%u (CBCMMT192)\n",
           test_passed, cavp.tot_tests);

    free_cavp(&cavp, CBC_OPERATION_MODE);
    return cavp.tot_tests - test_passed;
}

int cbc_mmt256(void)
{
    unsigned i;
    uint8_t *buffer;
    unsigned test_passed = 0;

    cavp_data cavp;

#ifdef C_SIMULATION
    parse_cavp(&cavp, "../tests/aesmmt/CBCMMT256.rsp", CBC_OPERATION_MODE);
#else // VIVADO_HLS
    parse_cavp(&cavp, "../../../../../tests/aesmmt/CBCMMT256.rsp", CBC_OPERATION_MODE);
#endif // C_SIMULATION

    /* Encryption tests */

    for (i = 0; i < cavp.enc_tests; ++i)
    {
        buffer = (uint8_t *) malloc((sizeof(uint8_t) * cavp.lc[i]).to_uint64());

        int ret = 0;

        AES_CBC_CIPHER(ENCRYPTION_MODE, 256 / 8, cavp.lp[i], cavp.k[i], cavp.i[i], cavp.p[i], buffer, ret);

        test_passed += eval_cavp(&cavp, buffer, NULL, i, true,
            0, CBC_OPERATION_MODE, CBCMMT256_VERBOSE);

        free(buffer);
    }

    /* Decryption tests */

    for (i = cavp.enc_tests; i < cavp.tot_tests; ++i)
    {
        buffer = (uint8_t *) malloc((sizeof(uint8_t) * cavp.lp[i]).to_uint64());

        int ret = 0;

        AES_CBC_CIPHER(DECRYPTION_MODE, 256 / 8, cavp.lc[i], cavp.k[i], cavp.i[i], cavp.c[i], buffer, ret);

        test_passed += eval_cavp(&cavp, buffer, NULL, i, false,
            0, CBC_OPERATION_MODE, CBCMMT256_VERBOSE);

        free(buffer);
    }

    printf("Info: test passed #%u out of #%u (CBCMMT256)\n",
           test_passed, cavp.tot_tests);

    free_cavp(&cavp, CBC_OPERATION_MODE);
    return cavp.tot_tests - test_passed;
}

#endif /* __CBC_TESTS_H__ */
