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
static uint8_t            locked = true;

//--------------------------------------------------------------------------------------------------
// Key Store
//--------------------------------------------------------------------------------------------------
void keystore_init() {
  locked = true;
  memset(&temp_key,    0, sizeof(temp_key));
  memset(&flash_cache, 0, sizeof(flash_cache));
}

void secret_locked(uint8_t value) {
  locked = value;
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

uint8_t keystore_store_secret(uint8_t *public_id, uint8_t *secret) {
  /* check EEPROM header identifier */
  uint32_t magic = read_uint32(flash_cache.header.magic);
  if (magic != 0xdeadbeef) {
    return THSM_STATUS_KEY_STORAGE_LOCKED;
  } else if (locked) {
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
    return THSM_STATUS_MEMORY_ERROR;
  } else if (locked) {
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

uint8_t keystore_check_counter(uint8_t *public_id, uint8_t *counter) {
  /* check EEPROM header identifier */
  uint32_t magic = read_uint32(flash_cache.header.magic);
  if (magic != 0xdeadbeef) {
    return THSM_STATUS_MEMORY_ERROR;
  } else if (locked) {
    return THSM_STATUS_KEY_STORAGE_LOCKED;
  }

  /* scan through secret entries */
  THSM_DB_SECRETS *secrets = &flash_cache.body.secrets;
  for (uint16_t i = 0; i < THSM_DB_SECRET_ENTRIES; i++) {
    if (!memcpy(secrets->entries[i].public_id, public_id, THSM_PUBLIC_ID_SIZE)) {
      uint8_t *nonce_ref  = flash_cache.body.counter.entries[i].value;
      uint8_t *nonce_act  = counter;
      uint32_t tstamp_ref = (nonce_ref[3] << 24) | (nonce_ref[4] << 16) | nonce_ref[5];
      uint32_t tstamp_act = (nonce_act[3] << 24) | (nonce_act[4] << 16) | nonce_act[5];

      /* compare session */
      if (memcmp(nonce_ref, nonce_act, 3) != 0) {
        return THSM_STATUS_OTP_INVALID;
      } else if (tstamp_act < tstamp_ref) {
        return THSM_STATUS_OTP_REPLAY;
      } else if ((tstamp_ref - tstamp_act) < THSM_OTP_DELTA_MAX) {

        /* copy and increment counter */
        memcpy(flash_cache.body.counter.entries[i].value, counter, THSM_AEAD_NONCE_SIZE);
        increment_nonce(flash_cache.body.counter.entries[i].value);

        return THSM_STATUS_OK;
      }
    }
  }

  return THSM_STATUS_ID_NOT_FOUND;
}

void keystore_update() {
  THSM_FLASH_STORAGE cached;

  /* update hash */
  sha1_ctx_t ctx;
  sha1_init(&ctx);
  sha1_update(&ctx, (uint8_t *)&flash_cache.body, sizeof(flash_cache.body));
  sha1_final (&ctx, flash_cache.header.digest);

  /* copy flash cache */
  memcpy(&cached, &flash_cache, sizeof(flash_cache));

  /* encrypt flash body */
  aes_cbc_encrypt((uint8_t *)&cached.body, (uint8_t *)&flash_cache.body, sizeof(flash_cache.body), flash_key, (THSM_KEY_SIZE * 2));

  /* save to flash */
  flash_update((uint8_t *)&cached, 0, sizeof(flash_cache));

  memset((uint8_t *)&cached, 0, sizeof(cached));
}

