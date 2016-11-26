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

void keystore_unlock(uint8_t *cipherkey) {
  /* load flash */
  uint8_t tmp[sizeof(THSM_FLASH_DB)];

  /* read entire flash */
  flash_read(tmp, 0, sizeof(tmp));
  memcpy(tmp, &flash_cache.db, sizeof(flash_cache.db));

  /* decrypt flash */
  // aes_cbc_decrypt(tmp2, tmp1, sizeof(tmp1), cipherkey);

  /* clear temporary buffer */
  memset(tmp, 0, sizeof(tmp));
}

uint8_t keystore_load_key(uint8_t *dst_key, uint8_t *dst_flags, uint32_t handle) {
  /* check if phantom key requested */
  if (handle == 0xffffffff) {
    memcpy(dst_key, &phantom_key, sizeof(phantom_key));
    return 1;
  }

  for (uint16_t i = 0; i < THSM_DB_KEY_ENTRIES; i++) {
    uint32_t tmp = read_uint32(flash_cache.db.keys.entries[i].handle);
    if (tmp == handle) {
      uint32_t flags = read_uint32(flash_cache.db.keys.entries[i].flags);
      write_uint32(dst_flags, flags);
      memcpy(dst_key, flash_cache.db.keys.entries[i].key, THSM_KEY_SIZE);

      return 1;
    }
  }

  return 0;
}
