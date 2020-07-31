#ifndef __TESTS_H__
#define __TESTS_H__

#include "utils.h"

/* RSA Simple Test Vectors */

#define RSA_SASP_VERBOSE 0

/*****************************************************************************/

int rsa_sasp(void)
{
    int ret;
    unsigned i;
    uint8_t *buffer;
    unsigned test_passed = 0;
    unsigned test_skipped = 0;

    cavp_data cavp;

#ifdef C_SIMULATION
    parse_cavp(&cavp, "../tests/sasp/RSASP1.fax", RSA_SASP);
#else // VIVADO_HLS
    parse_cavp(&cavp, "../../../../../tests/sasp/RSASP1.fax", RSA_SASP);
#endif // C_SIMULATION

    for (i = 0; i < cavp.tot_tests; ++i)
    {
        if (cavp.f[i] == true)
        {
            /* Skip tests that generate failures */
            test_skipped++;
            continue;
        }

        buffer = (uint8_t*) malloc(sizeof(uint8_t) * cavp.lp[i]);

        ret = rsa(cavp.ln[i], cavp.ld[i], cavp.lp[i], cavp.n[i], cavp.d[i],
                cavp.p[i], buffer);

        test_passed += eval_cavp(&cavp, buffer, cavp.lp[i], i,
                 ret == -1, RSA_SASP, RSA_SASP_VERBOSE);

        free(buffer);
    }

    printf("Info: test passed #%u out of #%u (RSASASP)\n",
           test_passed, cavp.tot_tests - test_skipped);

    free_cavp(&cavp, RSA_SASP);

    return cavp.tot_tests - test_passed - test_skipped;
}

#endif /* __TESTS_H__ */
