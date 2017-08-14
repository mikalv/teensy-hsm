#include "hmac.h"

//------------------------------------------------------------------------------
// GLobal Variables
//------------------------------------------------------------------------------
hmac_sha1_ctx_t hmac_sha1_ctx;

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
  sha1_init  (&(ctx->hash));
  sha1_update(&(ctx->hash), tmp, sizeof(tmp));
  sha1_update(&(ctx->hash), digest, sizeof(digest));
  sha1_final (&(ctx->hash), mac);

  /* clear context */
  memset(ctx, 0, sizeof(hmac_sha1_ctx_t));
}
