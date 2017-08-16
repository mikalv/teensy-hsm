#include "sha1-hmac.h"
#include "macros.h"

SHA1HMAC::SHA1HMAC()
{
    MEMCLR(ipad);
    MEMCLR(opad);
    ctx = SHA1();
}

SHA1HMAC::~SHA1HMAC()
{
    MEMCLR(ipad);
    MEMCLR(opad);
}

void SHA1HMAC::init(const uint8_t *key, uint32_t key_length)
{
    if (key_length > sizeof(this->ipad))
    {
        sha1_digest_t digest;
        ctx.update(key, key_length);
        ctx.final(digest);
        memcpy(this->ipad, digest.bytes, sizeof(digest.bytes));
        memcpy(this->opad, digest.bytes, sizeof(digest.bytes));
    }
    else
    {
        memcpy(this->ipad, key, key_length);
        memcpy(this->opad, key, key_length);
    }

    /* xor key with ipad */
    for (uint16_t i = 0; i < sizeof(ipad); i++)
    {
        ipad[i] ^= 0x36;
        opad[i] ^= 0x5c;
    }

    reset();
}

void SHA1HMAC::reset()
{
    /* update hash */
    ctx.reset();
    ctx.update(ipad, sizeof(ipad));
}

void SHA1HMAC::update(const uint8_t *data, uint32_t data_length)
{
    ctx.update(data, data_length);
}

void SHA1HMAC::final(sha1_digest_t &mac)
{
    sha1_digest_t digest;

    /* finalize hash */
    ctx.final(digest);
    ctx.update(opad, sizeof(opad));
    ctx.update(digest.bytes, sizeof(digest.bytes));
    ctx.final(mac);

    reset();
}

void SHA1HMAC::calculate(sha1_digest_t &mac, const uint8_t *data, uint32_t data_length)
{
    reset();
    update(data, data_length);
    final(mac);
}

bool SHA1HMAC::compare(const sha1_digest_t &mac, const uint8_t *data, uint32_t data_length)
{
    sha1_digest_t actual;
    calculate(actual, data, data_length);

    return memcmp(actual.bytes, mac.bytes, sizeof(mac.bytes)) == 0;
}
