//==================================================================================================
// Project : Teensy HSM
// Author  : Edi Permadi
// Repo    : https://github.com/edipermadi/teensy-hsm
//
// This file is part of TeensyHSM project containing the implementation of SHA1 and HMAC-SHA1.
//==================================================================================================

//--------------------------------------------------------------------------------------------------
// Macros
//--------------------------------------------------------------------------------------------------
#define ROTL_1(x) (((x) << 1) | ((x) >> 31))
#define ROTL_5(x) (((x) << 5) | ((x) >> 27))
#define ROTL_30(x)(((x) << 30) | ((x) >> 2))

//--------------------------------------------------------------------------------------------------
// HMAC-SHA1
//--------------------------------------------------------------------------------------------------
void hmac_reset() {
  memset(&hmac_sha1_ctx, 0, sizeof(hmac_sha1_ctx));
}

void hmac_sha1_init(hmac_sha1_ctx_t *ctx, uint8_t *key, uint16_t len)
{
  /* clear and initialize context */
  memset(ctx, 0, sizeof(hmac_sha1_ctx_t));

  if (len > sizeof(ctx->key))
  {
    sha1_init(&(ctx->hash));
    sha1_update(&(ctx->hash), key, len);
    sha1_final(&(ctx->hash), ctx->key);
  }
  else
  {
    memcpy(ctx->key, key, len);
  }

  /* xor key with ipad */
  uint8_t tmp[SHA1_BLOCK_SIZE_BYTES];
  for (uint16_t i = 0; i < sizeof(tmp); i++)
  {
    tmp[i] = 0x36 ^ ctx->key[i];
  }

  /* init and update hash */
  sha1_init(&(ctx->hash));
  sha1_update(&(ctx->hash), tmp, sizeof(tmp));
}

void hmac_sha1_update(hmac_sha1_ctx_t *ctx, uint8_t *data, uint16_t len)
{
  /* update hash */
  sha1_update(&(ctx->hash), data, len);
}

void hmac_sha1_final(hmac_sha1_ctx_t *ctx, uint8_t *mac)
{
  uint8_t digest[SHA1_DIGEST_SIZE_BYTES];
  uint8_t tmp[SHA1_BLOCK_SIZE_BYTES];

  /* finalize hash */
  sha1_final(&(ctx->hash), digest);

  /* xor key with opad */
  for (uint16_t i = 0; i < sizeof(tmp); i++)
  {
    tmp[i] = 0x5c ^ ctx->key[i];
  }

  /* reinitialize hash context */
  sha1_init(&(ctx->hash));
  sha1_update(&(ctx->hash), tmp, sizeof(tmp));
  sha1_update(&(ctx->hash), digest, sizeof(digest));
  sha1_final(&(ctx->hash), mac);

  /* clear context */
  memset(ctx, 0, sizeof(hmac_sha1_ctx_t));
}

//--------------------------------------------------------------------------------------------------
// SHA1
//--------------------------------------------------------------------------------------------------
static void sha1_init(sha1_ctx_t *ctx)
{
  memset(ctx, 0, sizeof(sha1_ctx_t));
  ctx->hashes[0] = 0x67452301;
  ctx->hashes[1] = 0xefcdab89;
  ctx->hashes[2] = 0x98badcfe;
  ctx->hashes[3] = 0x10325476;
  ctx->hashes[4] = 0xc3d2e1f0;
}

static void sha1_update(sha1_ctx_t *state, uint8_t *data, uint16_t length)
{
  /* update total length */
  state->msg_length += length;

  while (length > 0)
  {
    uint16_t written = state->buffer.length;
    if (written < sizeof(state->buffer.bytes))
    {
      uint32_t max = sizeof(state->buffer.bytes) - written;
      uint32_t step = (length > max) ? max : length;
      memcpy(&state->buffer.bytes[written], data, step);

      data += step;
      length -= step;
      written += step;
      state->buffer.length += step;
    }

    if (written >= sizeof(state->buffer.bytes))
    {
      sha1_step(state);
    }
  }
}

static void sha1_final(sha1_ctx_t *ctx, uint8_t *digest)
{
  uint32_t written = ctx->buffer.length;

  /* append padding */
  ctx->buffer.bytes[written] = 0x80;
  memset(&ctx->buffer.bytes[written + 1], 0, (sizeof(ctx->buffer.bytes) - (written + 1)));

  if (written > (sizeof(ctx->buffer.bytes) - 9))
  {
    sha1_step(ctx);
  }

  /* append length in bits */
  uint8_t *ptr = &ctx->buffer.bytes[sizeof(ctx->buffer.bytes) - sizeof(uint64_t)];
  uint64_t msg_length = ctx->msg_length << 3;
  *ptr++ = (uint8_t) (msg_length >> 56);
  *ptr++ = (uint8_t) (msg_length >> 48);
  *ptr++ = (uint8_t) (msg_length >> 40);
  *ptr++ = (uint8_t) (msg_length >> 32);
  *ptr++ = (uint8_t) (msg_length >> 24);
  *ptr++ = (uint8_t) (msg_length >> 16);
  *ptr++ = (uint8_t) (msg_length >> 8);
  *ptr++ = (uint8_t) (msg_length);

  /* run last round */
  sha1_step(ctx);

  for (uint16_t i = 0; i < SHA1_DIGEST_SIZE_WORDS; i++)
  {
    *digest++ = (uint8_t) (ctx->hashes[i] >> 24);
    *digest++ = (uint8_t) (ctx->hashes[i] >> 16);
    *digest++ = (uint8_t) (ctx->hashes[i] >> 8);
    *digest++ = (uint8_t) (ctx->hashes[i]);
  }

  /* clear context */
  memset(ctx, 0, sizeof(sha1_ctx_t));
}

static void sha1_step(sha1_ctx_t *ctx)
{

  uint32_t words[SHA1_BLOCK_SIZE_WORDS];
  uint32_t a, b, c, d, e;

  /* load block */
  uint8_t *p2 = ctx->buffer.bytes;
  for (uint16_t i = 0; i < SHA1_BLOCK_SIZE_WORDS; i++)
  {
    uint32_t tmp = 0;
    tmp |= *p2++ << 24;
    tmp |= *p2++ << 16;
    tmp |= *p2++ << 8;
    tmp |= *p2++ << 0;
    words[i] = tmp;
  }

  /* load hash */
  a = ctx->hashes[0];
  b = ctx->hashes[1];
  c = ctx->hashes[2];
  d = ctx->hashes[3];
  e = ctx->hashes[4];

  for (uint16_t i = 0; i < 80; i++)
  {
    uint32_t w;

    uint32_t t = (i < 16) ? words[i] : ROTL_1((ctx->words[i - 3] ^ ctx->words[i - 8] ^ ctx->words[i - 14] ^ ctx->words[i - 16]));
    ctx->words[i] = t;

    if (i < 20)
    {
      w = ROTL_5(a) + ((b & c) | ((~b) & d)) + e + t + 0x5a827999;
    }
    else if (i < 40)
    {
      w = ROTL_5(a) + (b ^ c ^ d) + e + t + 0x6ed9eba1;
    }
    else if (i < 60)
    {
      w = ROTL_5(a) + ((b & c) | (b & d) | (c & d)) + e + t + 0x8f1bbcdc;
    }
    else
    {
      w = ROTL_5(a) + (b ^ c ^ d) + e + t + 0xca62c1d6;
    }

    e = d;
    d = c;
    c = ROTL_30(b);
    b = a;
    a = w;
  }

  /* store hash */
  ctx->hashes[0] += a;
  ctx->hashes[1] += b;
  ctx->hashes[2] += c;
  ctx->hashes[3] += d;
  ctx->hashes[4] += e;

  /* clear buffer */
  memset(ctx->buffer.bytes, 0, sizeof(ctx->buffer.bytes));
  ctx->buffer.length = 0;
}
