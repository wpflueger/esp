#include "aes.h"
#include "ecb.h"
#include "cbc.h"
#include "gcm.h"

#include <mc_scverify.h>

#pragma hls_design top
#ifdef __CUSTOM_SIM__
void aes(
#else
void CCS_BLOCK(aes)(
#endif
        uint32_t oper_mode,
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
        int &ret)
{
    printf("oper_mode: %u\n", oper_mode);
    printf("encryption: %u\n", encryption);
    printf("key_bytes: %u\n", key_bytes);
    printf("iv_bytes: %u\n", iv_bytes);
    printf("input_bytes: %u\n", input_bytes);
    printf("aad_bytes: %u\n", aad_bytes);
    printf("tag_bytes: %u\n", tag_bytes);
    printf("key[%u]\n", MAX_KEY_BYTES);
    printf("iv[%u]\n", MAX_IV_BYTES);
    printf("in[%u]\n", MAX_IN_BYTES);
    printf("out[%u]\n", MAX_IN_BYTES);
    printf("aad[%u]\n", MAX_IN_BYTES);
    printf("tag[%u]\n", MAX_IN_BYTES);

    uint32_t ekey[EXP_KEY_SIZE] = { 0x0000 };
    uint32_t enc = (oper_mode == CTR_OPERATION_MODE ||
                    oper_mode == GCM_OPERATION_MODE) ?
                    ENCRYPTION_MODE : encryption;

    aes_expand(enc, key_bytes, key, ekey);

    switch (oper_mode)
    {
        case ECB_OPERATION_MODE:
            ret = aes_ecb_ctr_cipher(oper_mode, encryption, key_bytes,
                    iv_bytes, input_bytes, ekey, iv, in, out);
            break;

        case CTR_OPERATION_MODE:
            ret = aes_ecb_ctr_cipher(oper_mode, ENCRYPTION_MODE, key_bytes,
                    iv_bytes, input_bytes, ekey, iv, in, out);
            break;

        case CBC_OPERATION_MODE:
            ret = aes_cbc_cipher(encryption, key_bytes, input_bytes, iv_bytes,
                    ekey, iv, in, out);
            break;

        case GCM_OPERATION_MODE:
            ret = aes_gcm_cipher(encryption, key_bytes, input_bytes, iv_bytes,
                    aad_bytes, tag_bytes, ekey, iv, in, out, aad, tag);
        break;

        default:
            break;
    }
}
