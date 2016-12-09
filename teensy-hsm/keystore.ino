//--------------------------------------------------------------------------------------------------
// Global Variables
//--------------------------------------------------------------------------------------------------
static THSM_FLASH_STORAGE flash_cache;

//--------------------------------------------------------------------------------------------------
// Key Store
//--------------------------------------------------------------------------------------------------
void keystore_init() {
  memset(&flash_cache, 0, sizeof(flash_cache));
}

/**
   Unlock digest
   error code:
   0 no error
   1 flash not initialized
   2 wrong cipherkey
*/
uint8_t keystore_unlock(uint8_t *cipherkey) {
  uint8_t body[sizeof(THSM_FLASH_BODY)];
  uint8_t digest[SHA1_DIGEST_SIZE_BYTES];
  sha1_ctx_t ctx;

  /* read entire flash */
  flash_read((uint8_t *)&flash_cache, 0, sizeof(flash_cache));

  uint32_t magic = read_uint32(flash_cache.header.magic);
  if (magic != 0xdeadbeef) {
    return 1;
  }

  /* decrypt flash */
  aes_cbc_decrypt(body, (uint8_t *)&flash_cache.body, sizeof(flash_cache.body), cipherkey, (THSM_KEY_SIZE * 2));

  /* compare digest */
  sha1_init  (&ctx);
  sha1_update(&ctx, body, sizeof(body));
  sha1_final (&ctx, digest);

  /* compare digest */
  uint8_t matched = !memcmp(digest, flash_cache.header.digest, sizeof(digest));

  /* clear temporary buffer */
  memset(body,   0, sizeof(body));
  memset(digest, 0, sizeof(digest));

  /* clear flash cache if decryption failed */
  if (!matched) {
    memset(&flash_cache, 0, sizeof(flash_cache));
    return 2;
  }

  return 0;
}

uint8_t keystore_load_key(uint8_t *dst_key, uint32_t *dst_flags, uint32_t handle) {
  /* check if phantom key requested */
  if (handle == 0xffffffff) {
    memcpy(dst_key, &phantom_key, sizeof(phantom_key));
    return 1;
  }

  THSM_FLASH_BODY *body = &flash_cache.body;
  for (uint16_t i = 0; i < THSM_DB_KEY_ENTRIES; i++) {
    uint32_t tmp = read_uint32(body->keys.entries[i].handle);
    if (tmp == handle) {
      uint32_t flags = read_uint32(body->keys.entries[i].flags);
      *dst_flags = flags;
      memcpy(dst_key, body->keys.entries[i].key, THSM_KEY_SIZE);

      return 1;
    }
  }

  return 0;
}
