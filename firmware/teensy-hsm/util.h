#ifndef __UTIL_H__
#define __UTIL_H__

#include <stdint.h>
#include "storage.h"

class Util
{
public:
    static bool is_empty(uint8_t *nonce, uint32_t length);
    static void unpack_secret(secret_info_t &out, const uint8_t *secret);
    static void pack_secret(uint8_t *secret, const secret_info_t &out);
};

#endif
