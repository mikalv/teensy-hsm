//==================================================================================================
// Project : Teensy HSM
// Author  : Edi Permadi
// Repo    : https://github.com/edipermadi/teensy-hsm
//
// This file is part of TeensyHSM project containing the implementation persistent storage backed
// key and secret storage.
//==================================================================================================

//--------------------------------------------------------------------------------------------------
// Global Variables
//--------------------------------------------------------------------------------------------------
static THSM_FLASH_STORAGE flash_cache;
static uint8_t            temp_key[THSM_KEY_SIZE];
static uint8_t            flash_key[(THSM_KEY_SIZE * 2)];

//--------------------------------------------------------------------------------------------------
// Key Store
//--------------------------------------------------------------------------------------------------
void keystore_init() {
  memset(&temp_key,    0, sizeof(temp_key));
  memset(&flash_cache, 0, sizeof(flash_cache));
}

void secret_locked(uint8_t value) {
  if (value) {
    system_flags &= ~SYSTEM_FLAGS_SECRET_UNLOCKED;
  } else {
    system_flags |= SYSTEM_FLAGS_SECRET_UNLOCKED;
  }
}

uint8_t keystore_unlock(uint8_t *cipherkey) {
  uint8_t body[sizeof(THSM_FLASH_BODY)];

  /* read entire flash */
  flash_read((uint8_t *)&flash_cache, 0, sizeof(flash_cache));

  uint32_t magic = read_uint32(flash_cache.header.magic);
  if (magic != 0xdeadbeef) {
    return THSM_STATUS_MEMORY_ERROR;
  }

  /* decrypt flash */
  aes_cbc_decrypt(body, (uint8_t *)&flash_cache.body, sizeof(flash_cache.body), cipherkey, (THSM_KEY_SIZE * 2));
  memcpy(&flash_cache.body, body, sizeof(body));
  memset(body,   0, sizeof(body));

  /* compare digest */
  if (!sha1_compare((uint8_t *)&flash_cache.body, sizeof(flash_cache.body), flash_cache.header.digest)) {
    memset(&flash_cache, 0, sizeof(flash_cache));
    memset(flash_key,    0, sizeof(flash_key));
    return THSM_STATUS_KEY_STORAGE_LOCKED;
  } else {
    memcpy(flash_key, cipherkey, (THSM_KEY_SIZE * 2));
  }

  return THSM_STATUS_OK;
}

void keystore_store_key(uint32_t handle, uint32_t flags, uint8_t *key) {
  if (handle == 0xffffffff) {
    if (key == NULL) {
      memset(temp_key, 0, sizeof(temp_key));
    } else {
      memcpy(temp_key, key, sizeof(temp_key));
    }
  }

  /* scan through key entries */
  THSM_DB_KEYS *keys = &flash_cache.body.keys;
  for (uint16_t i = 0; i < THSM_DB_KEY_ENTRIES; i++) {
    uint32_t tmp = read_uint32(keys->entries[i].handle);
    if (tmp == handle) {
      if (key == NULL) {
        memset((uint8_t *)&keys->entries[i], 0, sizeof(THSM_DB_KEY_ENTRY));
      } else {
        write_uint32(keys->entries[i].flags, flags);
        memcpy(keys->entries[i].key, key, THSM_KEY_SIZE);
      }
    }
  }

  /* update cache hash */
  sha1_calculate((uint8_t *)&flash_cache.body, sizeof(flash_cache.body), flash_cache.header.digest);
}

uint8_t keystore_load_key(uint8_t *dst_key, uint32_t *dst_flags, uint32_t handle) {
  /* check EEPROM header identifier */
  uint32_t magic = read_uint32(flash_cache.header.magic);
  if (magic != 0xdeadbeef) {
    return THSM_STATUS_KEY_STORAGE_LOCKED;
  }

  /* check if phantom key requested */
  if (handle == 0xffffffff) {
    memcpy(dst_key, temp_key, sizeof(temp_key));
    return THSM_STATUS_OK;
  }

  /* scan through key entries */
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

uint8_t keystore_store_secret(uint8_t *public_id, uint8_t *key, uint8_t *nonce, uint32_t counter) {
  /* check EEPROM header identifier */
  uint32_t magic = read_uint32(flash_cache.header.magic);
  if (magic != 0xdeadbeef) {
    return THSM_STATUS_KEY_STORAGE_LOCKED;
  } else if (!(system_flags & SYSTEM_FLAGS_SECRET_UNLOCKED)) {
    return THSM_STATUS_KEY_STORAGE_LOCKED;
  }

  /* scan through secret entries */
  THSM_DB_SECRETS *secrets = &flash_cache.body.secrets;
  for (uint16_t i = 0; i < THSM_DB_SECRET_ENTRIES; i++) {
    if (!memcmp(secrets->entries[i].public_id, public_id, THSM_PUBLIC_ID_SIZE)) {
      return THSM_STATUS_ID_DUPLICATE;
    } else if (!memcmp(secrets->entries[i].public_id, public_id, THSM_PUBLIC_ID_SIZE)) {
      memcpy(secrets->entries[i].key,   key,   THSM_KEY_SIZE);
      memcpy(secrets->entries[i].nonce, nonce, THSM_AEAD_NONCE_SIZE);
      write_uint32(secrets->entries[i].counter, counter);

      /* update cache hash */
      sha1_calculate((uint8_t *)&flash_cache.body, sizeof(flash_cache.body), flash_cache.header.digest);
      return THSM_STATUS_OK;
    }
  }

  return THSM_STATUS_DB_FULL;
}

/**
   @param key, buffer to store AES key
   @param nonce, buffer to store AEAD nonce

*/
uint8_t keystore_load_secret(uint8_t *key, uint8_t *nonce, uint8_t *public_id) {
  /* check EEPROM header identifier */
  uint32_t magic = read_uint32(flash_cache.header.magic);
  if (magic != 0xdeadbeef) {
    return THSM_STATUS_MEMORY_ERROR;
  } else if (!(system_flags & SYSTEM_FLAGS_SECRET_UNLOCKED)) {
    return THSM_STATUS_KEY_STORAGE_LOCKED;
  }

  /* scan through secret entries */
  THSM_DB_SECRETS *secrets = &flash_cache.body.secrets;
  for (uint16_t i = 0; i < THSM_DB_SECRET_ENTRIES; i++) {
    if (!memcmp(secrets->entries[i].public_id, public_id, THSM_PUBLIC_ID_SIZE)) {
      memcpy(key,   secrets->entries[i].key,   THSM_KEY_SIZE);
      memcpy(nonce, secrets->entries[i].nonce, THSM_AEAD_NONCE_SIZE);
      return THSM_STATUS_OK;
    }
  }

  return THSM_STATUS_ID_NOT_FOUND;
}

uint8_t keystore_check_counter(uint8_t *public_id, uint32_t counter) {
  /* check EEPROM header identifier */
  uint32_t magic = read_uint32(flash_cache.header.magic);
  if (magic != 0xdeadbeef) {
    return THSM_STATUS_MEMORY_ERROR;
  } else if (!(system_flags & SYSTEM_FLAGS_SECRET_UNLOCKED)) {
    return THSM_STATUS_KEY_STORAGE_LOCKED;
  }

  /* scan through secret entries */
  THSM_DB_SECRETS *secrets = &flash_cache.body.secrets;
  for (uint16_t i = 0; i < THSM_DB_SECRET_ENTRIES; i++) {
    if (!memcmp(secrets->entries[i].public_id, public_id, THSM_PUBLIC_ID_SIZE)) {
      uint32_t counter_ref = read_uint32(secrets->entries[i].counter);
      if (counter_ref > counter) {
        return THSM_STATUS_OTP_REPLAY;
      } else if (counter_ref < counter) {
        return THSM_STATUS_OTP_INVALID;
      }

      /* increment counter and update EEPROM */
      write_uint32(secrets->entries[i].counter, (counter_ref + 1));
      keystore_update();
      return THSM_STATUS_OK;
    }
  }

  return THSM_STATUS_ID_NOT_FOUND;
}

void keystore_update() {
  THSM_FLASH_STORAGE cached;

  /* update cache hash */
  sha1_calculate((uint8_t *)&flash_cache.body, sizeof(flash_cache.body), flash_cache.header.digest);

  /* copy flash cache */
  memcpy(&cached, &flash_cache, sizeof(flash_cache));

  /* encrypt flash body */
  aes_cbc_encrypt((uint8_t *)&cached.body, (uint8_t *)&flash_cache.body, sizeof(flash_cache.body), flash_key, (THSM_KEY_SIZE * 2));

  /* save to flash */
  flash_update((uint8_t *)&cached, 0, sizeof(flash_cache));

  memset((uint8_t *)&cached, 0, sizeof(cached));
}

