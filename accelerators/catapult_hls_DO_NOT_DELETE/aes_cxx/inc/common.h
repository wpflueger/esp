#ifndef __COMMON_H__
#define __COMMON_H__

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#define BIT(x) (1 << (x))

#define GET32(ct, pt) ct = (((uint32_t)(pt)[0] << 24) ^ \
                            ((uint32_t)(pt)[1] << 16) ^ \
                            ((uint32_t)(pt)[2] <<  8) ^ \
                            ((uint32_t)(pt)[3] <<  0))

#define PUT32(ct, st) { (ct)[0] = (uint8_t)((uint32_t)(st) >> 24); \
                        (ct)[1] = (uint8_t)((uint32_t)(st) >> 16); \
                        (ct)[2] = (uint8_t)((uint32_t)(st) >>  8); \
                        (ct)[3] = (uint8_t)((uint32_t)(st) >>  0); }

#define PUT64(ct, st) { (ct)[0] = (uint8_t)((uint64_t)(st) >> 56ULL); \
                        (ct)[1] = (uint8_t)((uint64_t)(st) >> 48ULL); \
                        (ct)[2] = (uint8_t)((uint64_t)(st) >> 40ULL); \
                        (ct)[3] = (uint8_t)((uint64_t)(st) >> 32ULL); \
                        (ct)[4] = (uint8_t)((uint64_t)(st) >> 24ULL); \
                        (ct)[5] = (uint8_t)((uint64_t)(st) >> 16ULL); \
                        (ct)[6] = (uint8_t)((uint64_t)(st) >>  8ULL); \
                        (ct)[7] = (uint8_t)((uint64_t)(st) >>  0ULL); }

#endif /* __COMMON_H__ */
