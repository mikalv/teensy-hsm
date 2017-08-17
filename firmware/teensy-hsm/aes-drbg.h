#ifndef __AES_DRBG_H__
#define __AES_DRBG_H__

//------------------------------------------------------------------------------
// Imports
//------------------------------------------------------------------------------
#include "aes.h"

#define AES_DRBG_SEED_SIZE_BYTES  (AES_BLOCK_SIZE_BYTES + AES_KEY_SIZE_BYTES) // Size of CTR-DRBG entropy

//------------------------------------------------------------------------------
// Data Structure
//------------------------------------------------------------------------------
typedef struct
{
    uint8_t bytes[AES_DRBG_SEED_SIZE_BYTES];
} aes_drbg_entropy_t;

class AESDRBG
{
public:
    AESDRBG();
    void init(const aes_drbg_entropy_t &seed);
    int32_t generate(aes_state_t &random);
    void update(const aes_drbg_entropy_t &seed);
    void reseed(const aes_drbg_entropy_t &seed);
private:
    void clear();
    AES aes;
    aes_state_t key, value;
    uint64_t reseed_counter;
};

#endif
