#ifndef __UTIL_H__
#define __UTIL_H__

#include "sha1.h"

class Util{
public:
    void digest(sha1_digest_t &digest, uint8_t *data, uint32_t length);
};



#endif
