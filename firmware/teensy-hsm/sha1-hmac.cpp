#include "sha1-hmac.h"
#include "macros.h"

SHA1HMAC::SHA1HMAC(const buffer_t &key)
{
    MEMCLR(this->key);
    ctx = SHA1();

    if (key.length > sizeof(this->key))
    {
        sha1_digest_t digest;
        ctx.update(key);
        ctx.final(digest);
        memcpy(this->key, digest.bytes, sizeof(digest.bytes));
        ctx.reset();
    }
    else
    {
        memcpy(this->key, key.bytes, key.length);
    }

    reset();
}

SHA1HMAC::~SHA1HMAC()
{
    MEMCLR(key);
}

void SHA1HMAC::reset()
{
    /* xor key with ipad */
    uint8_t tmp[SHA1_BLOCK_SIZE_BYTES];
    for (uint16_t i = 0; i < sizeof(tmp); i++)
    {
        tmp[i] = 0x36 ^ this->key[i];
    }

    /* update hash */
    buffer_t data = buffer_t(tmp, sizeof(tmp));
    ctx.update(data);
}

int32_t SHA1HMAC::update(const buffer_t &data)
{
    return ctx.update(data);
}

void SHA1HMAC::final(sha1_digest_t &mac)
{
    sha1_digest_t digest;
    uint8_t tmp[SHA1_BLOCK_SIZE_BYTES];
    buffer_t data1 = buffer_t(tmp, sizeof(tmp));
    buffer_t data2 = buffer_t(digest.bytes, sizeof(digest.bytes));

    /* finalize hash */
    ctx.final(digest);

    /* xor key with opad */
    for (uint16_t i = 0; i < sizeof(tmp); i++)
    {
        tmp[i] = 0x5c ^ this->key[i];
    }

    /* reinitialize hash context */
    ctx.reset();
    ctx.update(data1);
    ctx.update(data2);
    ctx.final(mac);

    reset();
}

int32_t SHA1HMAC::calculate(sha1_digest_t &mac, const buffer_t &data)
{
    ctx.reset();
    int32_t ret = ctx.update(data);
    if(ret >= 0){
        ctx.final(mac);
    }

    ctx.reset();
    return ret;
}

bool SHA1HMAC::compare(const buffer_t &data, const sha1_digest_t &mac)
{
    sha1_digest_t actual;
    calculate(actual, data);

    return memcmp(actual.bytes, mac.bytes, sizeof(mac.bytes)) == 0;
}
