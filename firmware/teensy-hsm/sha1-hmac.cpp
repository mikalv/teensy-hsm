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

void SHA1HMAC::init(const buffer_t &key)
{
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

	/* xor key with ipad */
	for (uint16_t i = 0; i < sizeof(ipad); i++)
	{
		ipad[i] ^= 0x36;
		opad[i] ^= 0x5c;
	}

	reset();
}

void SHA1HMAC::init(const uint8_t *key, uint32_t key_length)
{
	buffer_t tmp = buffer_t(key, key_length);
	init(tmp);
}

void SHA1HMAC::reset()
{
	/* update hash */
	buffer_t data = buffer_t(ipad, sizeof(ipad));
	ctx.reset();
	ctx.update(data);
}

int32_t SHA1HMAC::update(const buffer_t &data)
{
	return ctx.update(data);
}

int32_t SHA1HMAC::update(const uint8_t *data, uint32_t data_length)
{
	buffer_t tmp = buffer_t(data, data_length);
	return update(tmp);
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

int32_t SHA1HMAC::calculate(sha1_digest_t &mac, const uint8_t *data, uint32_t data_length)
{
	buffer_t tmp = buffer_t(data, data_length);
	return calculate(mac, tmp);
}

bool SHA1HMAC::compare(const sha1_digest_t &mac, const buffer_t &data)
{
	sha1_digest_t actual;
	calculate(actual, data);

	return memcmp(actual.bytes, mac.bytes, sizeof(mac.bytes)) == 0;
}

bool SHA1HMAC::compare(const sha1_digest_t &mac, const uint8_t *data, uint32_t data_length)
{
	sha1_digest_t actual;
	calculate(actual, data, data_length);

	return memcmp(actual.bytes, mac.bytes, sizeof(mac.bytes)) == 0;
}
