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

#define RESEED_COUNTER_VALUE 0x0001000000000000

AESDRBG::AESDRBG()
{
    clear();
    initialized = false;
    reseed_counter = 0;
}

void AESDRBG::init(const aes_drbg_entropy_t &seed)
{
    initialized = false;
    reseed(seed);
}

void AESDRBG::reseed(const aes_drbg_entropy_t &seed)
{
    if (!initialized)
    {
        initialized = true;

        clear();
        aes.init(key);
    }

    /* derive key and value from seed */
    update(seed);

    /* initialize with derived key */
    aes.init(key);
    reseed_counter = RESEED_COUNTER_VALUE;
}

int32_t AESDRBG::generate(aes_state_t &random)
{
    if (!initialized)
    {
        return ERROR_CODE_DRBG_NOT_INITIALIZED;
    }
    else if (!reseed_counter)
    {
        return ERROR_CODE_DRBG_EXHAUSTED;
    }

    reseed_counter--;
    AES::state_increment(value);
    aes.encrypt(random, value);

    return ERROR_CODE_NONE;
}

int32_t AESDRBG::generate(buffer_t &output, uint32_t length)
{
    if (length > sizeof(output.bytes))
    {
        return ERROR_CODE_INVALID_REQUEST;
    }

    MEMCLR(output);
    output.length = length;
    uint8_t *ptr = output.bytes;

    while (length)
    {
        aes_state_t random;
        int32_t ret = generate(random);
        if (ret < 0)
        {
            return ret;
        }

        uint32_t step = MIN(length, sizeof(random.bytes));
        memcpy(ptr, random.bytes, step);

        ptr += step;
        length -= step;
    }

    return ERROR_CODE_NONE;
}

int32_t AESDRBG::generate(uint8_t *buffer, uint32_t length)
{
    aes_state_t random;
    while (length)
    {
        uint32_t step = MIN(length, sizeof(random.bytes));
        int ret = generate(random);
        if (ret < 0)
        {
            return ret;
        }
        buffer = AES::state_copy(buffer, random, step);

        length -= step;
    }

    return ERROR_CODE_NONE;
}

void AESDRBG::update(const aes_drbg_entropy_t &seed)
{
    aes_state_t left, right, seed_left, seed_right;

    uint8_t *ptr = (uint8_t *) seed.bytes;
    ptr = AES::state_copy(seed_left, ptr);
    AES::state_copy(seed_right, ptr);

    AES::state_increment(value);
    aes.encrypt(left, value);
    AES::state_xor(key, left, seed_left);

    AES::state_increment(value);
    aes.encrypt(right, value);
    AES::state_xor(value, right, seed_right);
}

void AESDRBG::clear()
{
    MEMCLR(key);
    MEMCLR(value);
}
