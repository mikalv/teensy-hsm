#ifndef __SHA1_HMAC_H__
#define __SHA1_HMAC_H__

#include <stdint.h>
#include "sha1.h"
#include "buffer.h"

class SHA1HMAC
{
public:
    SHA1HMAC(const buffer_t &key);
    ~SHA1HMAC();
    void reset();
    int32_t update(const buffer_t &data);
    void final(sha1_digest_t &digest);
    int32_t calculate(sha1_digest_t &mac, const buffer_t &data);
    bool compare(const buffer_t &data, const sha1_digest_t &mac);
private:
    SHA1 ctx;
    uint8_t ipad[SHA1_BLOCK_SIZE_BYTES];
    uint8_t opad[SHA1_BLOCK_SIZE_BYTES];
};
#endif
