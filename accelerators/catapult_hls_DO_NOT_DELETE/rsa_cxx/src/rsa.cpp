#include "rsa.h"

#include "bn_add.h"
#include "bn_mul.h"
#include "bn_mod.h"
#include "bn_exp.h"

int rsa(uint32_t n_len,
        uint32_t e_len,
        uint32_t in_len,
        uint8_t n[RSA_MAX_BLOCK_SIZE],
        uint8_t e[RSA_MAX_BLOCK_SIZE],
        uint8_t in[RSA_MAX_BLOCK_SIZE],
        uint8_t out[RSA_MAX_BLOCK_SIZE])
{
#pragma HLS INTERFACE s_axilite port=n_len
#pragma HLS INTERFACE s_axilite port=e_len
#pragma HLS INTERFACE s_axilite port=in_len
#pragma HLS INTERFACE s_axilite port=return
#pragma HLS INTERFACE m_axi depth=rsa_max_addr_mem port=n offset=slave
#pragma HLS INTERFACE m_axi depth=rsa_max_addr_mem port=e offset=slave
#pragma HLS INTERFACE m_axi depth=rsa_max_addr_mem port=in offset=slave
#pragma HLS INTERFACE m_axi depth=rsa_max_addr_mem port=out offset=slave

    BIGNUM bn_n;
    BIGNUM bn_e;
    BIGNUM bn_in;
    BIGNUM bn_ret;

    BN_bin2bn(in, in_len, &bn_in);
    BN_bin2bn(n, n_len, &bn_n);
    BN_bin2bn(e, e_len, &bn_e);

    BN_mod_exp_mont(&bn_ret, &bn_in, &bn_e, &bn_n);

    BN_bn2binpad(&bn_ret, out, in_len);

    return 0;
}
