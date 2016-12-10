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

uint8_t keystore_unlock(uint8_t *cipherkey) {
  uint8_t body[sizeof(THSM_FLASH_BODY)];
  uint8_t digest[SHA1_DIGEST_SIZE_BYTES];
  sha1_ctx_t ctx;

  /* read entire flash */
  flash_read((uint8_t *)&flash_cache, 0, sizeof(flash_cache));

  uint32_t magic = read_uint32(flash_cache.header.magic);
  if (magic != 0xdeadbeef) {
    return THSM_STATUS_MEMORY_ERROR;
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
    return THSM_STATUS_KEY_STORAGE_LOCKED;
  }

  return THSM_STATUS_OK;
}

uint8_t keystore_load_key(uint8_t *dst_key, uint32_t *dst_flags, uint32_t handle) {
  /* check EEPROM header identifier */
  uint32_t magic = read_uint32(flash_cache.header.magic);
  if (magic != 0xdeadbeef) {
    return THSM_STATUS_KEY_STORAGE_LOCKED;
  }

  /* check if phantom key requested */
  if (handle == 0xffffffff) {
    memcpy(dst_key, &phantom_key, sizeof(phantom_key));
    return THSM_STATUS_OK;
  }

  /* scan through key enrties */
  THSM_DB_KEYS *keys = &flash_cache.body.keys;
  for (uint16_t i = 0; i < THSM_DB_KEY_ENTRIES; i++) {
    uint32_t tmp = read_uint32(keys->entries[i].handle);
    if (tmp == handle) {
      uint32_t flags = read_uint32(keys->entries[i].flags);
      *dst_flags = flags;
      memcpy(dst_key, keys->entries[i].key, THSM_KEY_SIZE);

      return THSM_STATUS_OK;
    }
  }

  return THSM_STATUS_KEY_HANDLE_INVALID;
}

uint8_t keystore_store_secret(uint8_t *public_id, uint8_t *secret) {
  /* check EEPROM header identifier */
  uint32_t magic = read_uint32(flash_cache.header.magic);
  if (magic != 0xdeadbeef) {
    return THSM_STATUS_KEY_STORAGE_LOCKED;
  }

  /* scan through secret entries */
  THSM_DB_SECRETS *secrets = &flash_cache.body.secrets;
  for (uint16_t i = 0; i < THSM_DB_SECRET_ENTRIES; i++) {
    if (!memcpy(secrets->entries[i].public_id, public_id, THSM_PUBLIC_ID_SIZE)) {
      return THSM_STATUS_ID_DUPLICATE;
    } else if (!memcmp(secrets->entries[i].public_id, public_id, THSM_PUBLIC_ID_SIZE)) {
      memcpy(secrets->entries[i].secret, secret, THSM_AEAD_SIZE);
      return THSM_STATUS_OK;
    }
  }

  return THSM_STATUS_DB_FULL;
}

uint8_t keystore_load_secret(uint8_t *secret, uint8_t *public_id) {
  /* check EEPROM header identifier */
  uint32_t magic = read_uint32(flash_cache.header.magic);
  if (magic != 0xdeadbeef) {
    return THSM_STATUS_KEY_STORAGE_LOCKED;
  }

  /* scan through secret entries */
  THSM_DB_SECRETS *secrets = &flash_cache.body.secrets;
  for (uint16_t i = 0; i < THSM_DB_SECRET_ENTRIES; i++) {
    if (!memcpy(secrets->entries[i].public_id, public_id, THSM_PUBLIC_ID_SIZE)) {
      memcpy(secret, secrets->entries[i].secret, THSM_AEAD_SIZE);
      return THSM_STATUS_OK;
    }
  }

  return THSM_STATUS_ID_NOT_FOUND;
}

