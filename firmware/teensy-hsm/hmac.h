#ifndef __HMAC_H__
#define __HMAC_H__

#include <stdint.h>
#include "sha1.h"

typedef struct
{
  uint8_t key[SHA1_BLOCK_SIZE_BYTES];
  sha1_ctx_t hash;
} hmac_sha1_ctx_t;

void hmac_sha1_init(hmac_sha1_ctx_t *ctx, uint8_t *key, uint16_t len);
void hmac_sha1_update(hmac_sha1_ctx_t *ctx, uint8_t *data, uint16_t len);
void hmac_sha1_final(hmac_sha1_ctx_t *ctx, uint8_t *mac);

#endif
