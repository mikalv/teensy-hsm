//======================================================================================================================
// Project : Teensy HSM
// Author  : Edi Permadi
// Repo    : https://github.com/edipermadi/teensy-hsm
//
// This file is part of TeensyHSM project utility class
//======================================================================================================================

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
