//======================================================================================================================
// Project : Teensy HSM
// Author  : Edi Permadi
// Repo    : https://github.com/edipermadi/teensy-hsm
//
// This file is part of TeensyHSM project utility class
//======================================================================================================================

#include <string.h>
#include "util.h"

bool Util::is_empty(uint8_t *data, uint32_t length)
{
    for (int i = 0; i < length && data; i++)
    {
        if (data[i])
        {
            return false;
        }
    }

    return true;
}


void Util::unpack_secret(secret_info_t &out, const uint8_t *secret)
{
    memcpy(out.key, secret, sizeof(out.key));
    secret += sizeof(out.key);
    memcpy(out.uid, secret, sizeof(out.uid));
}

void Util::pack_secret(uint8_t *out, const secret_info_t &secret)
{
    memcpy(out, secret.key, sizeof(secret.key));
    out += sizeof(secret.key);
    memcpy(out, secret.uid, sizeof(secret.uid));
}


