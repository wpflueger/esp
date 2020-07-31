#ifndef __RSA_H__
#define __RSA_H__

#include "bn.h"

#ifndef C_SIMULATION
#include <hls_stream.h>
#endif /* C_SIMULATION */

#define RSA_MAX_BLOCK_SIZE 65536
const int rsa_max_addr_mem = 65536;

int rsa(uint32_t n_len,
        uint32_t e_len,
        uint32_t in_len,
        uint8_t n[RSA_MAX_BLOCK_SIZE],
        uint8_t e[RSA_MAX_BLOCK_SIZE],
        uint8_t in[RSA_MAX_BLOCK_SIZE],
        uint8_t out[RSA_MAX_BLOCK_SIZE]);

#endif /* __RSA_H__ */
