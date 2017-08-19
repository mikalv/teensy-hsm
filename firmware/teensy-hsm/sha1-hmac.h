#ifndef __SHA1_HMAC_H__
#define __SHA1_HMAC_H__

#include <stdint.h>
#include "sha1.h"
#include "buffer.h"

class SHA1HMAC
{
public:
    SHA1HMAC();
    ~SHA1HMAC();
    void init(const uint8_t *key, uint32_t key_length);
    void reset();
    void update(const uint8_t *data, uint32_t data_length);
    void final(sha1_digest_t &digest);
    void calculate(sha1_digest_t &mac, const uint8_t *data, uint32_t data_length, const uint8_t *key, uint32_t key_length);
    bool compare(const sha1_digest_t &mac, const buffer_t &data, const uint8_t *key, uint32_t key_length);
    bool compare(const sha1_digest_t &mac, const uint8_t *data, uint32_t data_length, const uint8_t *key, uint32_t key_length);
private:
    SHA1 ctx;
    uint8_t ipad[SHA1_BLOCK_SIZE_BYTES];
    uint8_t opad[SHA1_BLOCK_SIZE_BYTES];
};
#endif
