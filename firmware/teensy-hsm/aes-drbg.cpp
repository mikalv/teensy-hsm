//==================================================================================================
// Project : Teensy HSM
// Author  : Edi Permadi
// Repo    : https://github.com/edipermadi/teensy-hsm
//
// This file is part of TeensyHSM project containing the implementation of AES-128 based CTR_DRBG
// deterministic random bit generator seeded by whitened ADC noise.
//==================================================================================================

#include <string.h>
#include "aes-drbg.h"
#include "macros.h"
#include "error.h"

#define RESEE_COUNTER_VALUE 0x0001000000000000

AESDRBG::AESDRBG::()
{
    clear();
    reseed_counter = 0;
}

// Instantiate_algorithm (entropy_input, nonce, personalization_string, security_strength)
void AESDRBG::init(const aes_drbg_entropy_t &seed)
{
    clear();

    /* derive key and value from seed */
    aes.init(key);
    update(seed);

    /* initialize with derived key */
    aes.init(key);
    reseed_counter = RESEED_COUNTER_VALUE;
}

int32_t AESDRBG::generate(aes_state_t &random)
{
    if (reseed_counter == 0)
    {
        return ERROR_CODE_DRBG_EXHAUSTED;
    }

    reseed_counter--;
    AES::state_increment(value);
    aes.encrypt(random, value);

    return ERROR_CODE_NONE;
}

void AESDRBG::update(const aes_drbg_entropy_t &seed)
{
    aes_state_t left, right, seed_left, seed_right;
    AES::state_fill(seed_left, seed.bytes);
    AES::state_fill(seed_right, seed.bytes + sizeof(seed_right.bytes));

    AES::state_increment(value);
    aes.encrypt(left, value);
    AES::state_xor(key, left, seed_left);

    AES::state_increment(value);
    aes.encrypt(right, value);
    AES::state_xor(value, right, seed_right);
}

void AESDRBG::reseed(const aes_drbg_entropy_t &seed)
{
    /* derive key and value from seed */
    update(seed);

    /* initialize with derived key */
    aes.init(key);
    reseed_counter = RESEED_COUNTER_VALUE;
}

void AESDRBG::clear()
{
    MEMCLR(key);
    MEMCLR(value);
}
