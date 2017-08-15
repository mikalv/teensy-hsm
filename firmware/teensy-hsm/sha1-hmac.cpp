#include "sha1-hmac.h"
#include "macros.h"

SHA1HMAC::SHA1HMAC(const buffer_t &key)
{
    MEMCLR(ipad);
    MEMCLR(opad);
    ctx = SHA1();

    if (key.length > sizeof(this->ipad))
    {
        sha1_digest_t digest;
        ctx.update(key);
        ctx.final(digest);
        memcpy(this->ipad, digest.bytes, sizeof(digest.bytes));
        memcpy(this->opad, digest.bytes, sizeof(digest.bytes));
    }
    else
    {
        memcpy(this->ipad, key.bytes, key.length);
        memcpy(this->opad, key.bytes, key.length);
    }

    reset();
}

SHA1HMAC::~SHA1HMAC()
{
    MEMCLR(ipad);
    MEMCLR(opad);
}

void SHA1HMAC::reset()
{
    /* xor key with ipad */
    for (uint16_t i = 0; i < sizeof(ipad); i++)
    {
        ipad[i] ^= 0x36;
        opad[i] ^= 0x5c;
    }

    /* update hash */
    buffer_t data = buffer_t(ipad, sizeof(ipad));
    ctx.update(data);
}

int32_t SHA1HMAC::update(const buffer_t &data)
{
    return ctx.update(data);
}

void SHA1HMAC::final(sha1_digest_t &mac)
{
    sha1_digest_t digest;
    buffer_t data1 = buffer_t(opad, sizeof(opad));
    buffer_t data2 = buffer_t(digest.bytes, sizeof(digest.bytes));

    /* finalize hash */
    ctx.final(digest);
    ctx.update(data1);
    ctx.update(data2);
    ctx.final(mac);

    reset();
}

int32_t SHA1HMAC::calculate(sha1_digest_t &mac, const buffer_t &data)
{
    ctx.reset();
    int32_t ret = ctx.update(data);
    if (ret >= 0)
    {
        ctx.final(mac);
    }
    else
    {
        ctx.reset();
    }

    return ret;
}

bool SHA1HMAC::compare(const buffer_t &data, const sha1_digest_t &mac)
{
    sha1_digest_t actual;
    calculate(actual, data);

    return memcmp(actual.bytes, mac.bytes, sizeof(mac.bytes)) == 0;
}
