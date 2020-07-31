#ifndef __AES_H__
#define __AES_H__

#include "defines.h"

//#ifndef C_SIMULATION
//#include <ac_int.h>
//#include <hls_stream.h>
//#endif // C_SIMULATION

void aes(uint32_t oper_mode,
        uint32_t encryption,
        uint32_t key_bytes,
        uint32_t iv_bytes,
        uint32_t input_bytes,
        uint32_t aad_bytes,
        uint32_t tag_bytes,
        uint8_t key[MAX_KEY_BYTES],
        uint8_t iv[MAX_IV_BYTES],
        uint8_t in[MAX_IN_BYTES],
        uint8_t out[MAX_IN_BYTES],
        uint8_t aad[MAX_IN_BYTES],
        uint8_t tag[MAX_IN_BYTES],
        int &ret);

#endif /* __AES_H__ */
