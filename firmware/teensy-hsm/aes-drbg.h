#ifndef __DRBG_H__
#define  __DRBG_H

//------------------------------------------------------------------------------
// Imports
//------------------------------------------------------------------------------
#include <stdint.h>
#include "aes.h"

#define AES_CTR_DRBG_SEED_SIZE    32 // Size of CTR-DRBG entropy

//------------------------------------------------------------------------------
// Data Structure
//------------------------------------------------------------------------------
typedef struct
{
    uint8_t value[AES_BLOCK_SIZE_BYTES];
    uint8_t key[AES_BLOCK_SIZE_BYTES];
    uint8_t counter[AES_CTR_DRBG_SEED_SIZE];
} drbg_ctx_t;

class AESDRBG
{
public:
    void init();
    void update();
    void reseed();
    void generate();
};

#endif
