//--------------------------------------------------------------------------------------------------
// Key Store
//--------------------------------------------------------------------------------------------------
void keystore_unlock(uint8_t *cipherkey) {
  /* load flash */
  uint8_t tmp1[sizeof(THSM_DB_KEYS)];
  uint8_t tmp2[sizeof(THSM_DB_KEYS)];
  
  flash_read(offsetof(THSM_FLASH_LAYOUT, keys), tmp1, sizeof(tmp1));

  /* decrypt flash */
  aes_cbc_decrypt(tmp2, tmp1, sizeof(tmp1), cipherkey);
  aes_cbc_decrypt(tmp1, tmp2, sizeof(tmp2), cipherkey + THSM_BLOCK_SIZE);

  /* copy decrypted key database */
  memcpy(&db_keys, tmp1, sizeof(db_keys));

  /* clear temporary buffer */
  memset(tmp1, 0, sizeof(tmp1));
  memset(tmp2, 0, sizeof(tmp2));
}

uint8_t load_key(uint8_t *dst_key, uint8_t *dst_flags, uint32_t handle) {
  /* check if phantom key requested */
  if (handle == 0xffffffff) {
    memcpy(dst_key, &phantom_key, sizeof(phantom_key));
    return 1;
  }

  for (uint i = 0; i < THSM_DB_KEY_ENTRIES; i++) {
    uint32_t tmp = read_uint32(db_keys.entries[i].handle);
    if (tmp == handle) {
      uint32_t flags = read_uint32(db_keys.entries[i].flags);
      write_uint32(dst_flags, flags);
      for (int j = 0; j < THSM_BLOCK_SIZE; j++) {
        dst_key[j] = db_keys.entries[i].bytes[j];
      }

      return 1;
    }
  }

  return 0;
}
