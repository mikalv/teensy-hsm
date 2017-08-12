//======================================================================================================================
// Project : Teensy HSM
// Author  : Edi Permadi
// Repo    : https://github.com/edipermadi/teensy-hsm
//
// This file is part of TeensyHSM project utility class
//======================================================================================================================

#include "util.h"

void Util::digest(sha1_digest_t &digest, uint8_t *data, uint32_t length)
{
    SHA1 sha1 = SHA1();
    sha1.update(data, length);
    sha1.final(digest);
}
