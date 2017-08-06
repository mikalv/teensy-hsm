//==================================================================================================
// Project : Teensy HSM
// Author  : Edi Permadi
// Repo    : https://github.com/edipermadi/teensy-hsm
//
// This file is part of TeensyHSM project containing the implementation of setup console
//==================================================================================================

//--------------------------------------------------------------------------------------------------
// Defines
//--------------------------------------------------------------------------------------------------
#define SETUP_DEBUG 1

//--------------------------------------------------------------------------------------------------
// Global Variables
//--------------------------------------------------------------------------------------------------
static uint8_t  setup_buffer[512];
static uint16_t setup_buffer_len = 0;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------
void setup_reset() {
  setup_buffer_len = 0;
  memset(setup_buffer, 0, sizeof(setup_buffer));
  Serial.print("\r\n> ");
}

void setup_run() {
  uint8_t nl_ctr = 0;

  /* clear buffer */
  setup_reset();

  while (1) {
    if (Serial.available()) {
      uint8_t b = Serial.read();

      nl_ctr = ((b == '\r') || (b == '\n')) ? (nl_ctr + 1) : 0;
      if (nl_ctr == '\n') {
        Serial.println("\r\nexit");
        return;
      } else if (b == '\t') {
        continue;
      } else if (b == '\b') {
        if (setup_buffer_len > 0) {
          --setup_buffer_len;
          Serial.print(b, BYTE);
        }
      } else if ((b == '\r') || (b == '\n')) {
        Serial.print("\r\n");

        /* terminate buffer */
        setup_buffer_len = (setup_buffer_len >= sizeof(setup_buffer)) ? (sizeof(setup_buffer) - 1) : setup_buffer_len;
        setup_buffer[setup_buffer_len] = 0;

        setup_dispatch();

        setup_reset();
      } else if (((b >= ' ') || (b <= '~')) && (setup_buffer_len < sizeof(setup_buffer))) {
        Serial.print(b, BYTE);
        setup_buffer[setup_buffer_len++] = b;
      }
    }
  }
}

static void setup_dispatch() {
  uint8_t ret = 0;
  if (!memcmp(setup_buffer, "help", 4)) {
    ret = setup_help(setup_buffer + 4);
  } else  if (!memcmp(setup_buffer, "db.erase", 8)) {
    ret = setup_db_erase(setup_buffer + 8);
  } else if (!memcmp(setup_buffer, "db.init", 7)) {
    ret = setup_db_init(setup_buffer + 7);
  } else if (!memcmp(setup_buffer, "db.load", 7)) {
    ret = setup_db_load(setup_buffer + 7);
  } else if (!memcmp(setup_buffer, "db.store.auto", 13)) {
    ret = setup_db_store_auto(setup_buffer + 13);
  } else if (!memcmp(setup_buffer, "db.store", 8)) {
    ret = setup_db_store(setup_buffer + 8);
  }  else if (!memcmp(setup_buffer, "db.status", 9)) {
    ret = setup_db_status(setup_buffer + 9);
  } else if (!memcmp(setup_buffer, "db.key.show", 11)) {
    ret = setup_db_key_show(setup_buffer + 11);
  } else if (!memcmp(setup_buffer, "db.key.delete", 13)) {
    ret = setup_db_key_delete(setup_buffer + 13);
  } else if (!memcmp(setup_buffer, "db.key.generate", 15)) {
    ret = setup_db_key_generate(setup_buffer + 15);
  } else if (!memcmp(setup_buffer, "db.key.update", 13)) {
    ret = setup_db_key_update(setup_buffer + 13);
  } else if (!memcmp(setup_buffer, "db.secret.show", 14)) {
    ret = setup_db_secret_show(setup_buffer + 14);
  } else if (!memcmp(setup_buffer, "db.secret.delete", 16)) {
    ret = setup_db_secret_delete(setup_buffer + 16);
  } else if (!memcmp(setup_buffer, "db.secret.generate", 18)) {
    ret = setup_db_secret_generate(setup_buffer + 18);
  } else if (!memcmp(setup_buffer, "db.secret.update", 16)) {
    ret = setup_db_secret_update(setup_buffer + 16);
  }

  if (!ret) {
    Serial.print("err");
  }
}

static uint8_t setup_help(uint8_t *ptr) {
  Serial.println("db.erase");
  Serial.println("db.init");
  Serial.println("db.load cipherkey");
  Serial.println("db.store cipherkey");
  Serial.println("db.store.auto");
  Serial.println("db.status");
  Serial.println("db.key.show slot_number");
  Serial.println("db.key.delete slot_number");
  Serial.println("db.key.generate slot_number handle flags");
  Serial.println("db.key.update slot_number handle flags payload");
  Serial.println("db.secret.show slot_number");
  Serial.println("db.secret.delete slot_number");
  Serial.println("db.secret.generate");
  Serial.println("db.secret.update");

  Serial.print("ok");
  return 1;
}

static uint8_t setup_db_erase(uint8_t *ptr) {
  memset(&flash_cache, 0xff, sizeof(flash_cache));
  flash_update((uint8_t *)&flash_cache, 0, sizeof(flash_cache));
  Serial.print("ok");
  return 1;
}

static uint8_t setup_db_init(uint8_t *ptr) {
  /* set all to 0x00 */
  memset(&flash_cache, 0, sizeof(flash_cache));
  write_uint32(flash_cache.header.magic, 0xdeadbeef);

  /* update cache hash */
  sha1_calculate((uint8_t *)&flash_cache.body, sizeof(flash_cache.body), flash_cache.header.digest);

  Serial.print("ok");
  return 1;
}

static uint8_t setup_db_load(uint8_t *buffer) {
  uint8_t cipherkey[THSM_KEY_SIZE * 2];
  uint8_t plaintext[sizeof(flash_cache.body)];

  /* load cipherkey */
  if (buffer_load_hex(cipherkey, &buffer, sizeof(cipherkey)) != sizeof(cipherkey)) {
    Serial.println("failed to load cipherkey");
    return 0;
  }

  /* read entire flash */
  flash_read((uint8_t *)&flash_cache, 0, sizeof(flash_cache));
  uint32_t magic = read_uint32(flash_cache.header.magic);
  if (magic != 0xdeadbeef) {
    Serial.println("invalid header");
    return 0;
  }

  /* decrypt */
  aes_cbc_decrypt(plaintext, (uint8_t *)&flash_cache.body, sizeof(flash_cache.body), cipherkey, sizeof(cipherkey));
  memcpy((uint8_t *)&flash_cache.body, plaintext, sizeof(plaintext));
  memset(cipherkey, 0, sizeof(cipherkey));
  memset(plaintext, 0, sizeof(plaintext));

  /* compare hash */
  if (!sha1_compare((uint8_t *)&flash_cache.body, sizeof(flash_cache.body), flash_cache.header.digest)) {
    Serial.println("hash mismatch");
    return 0;
  }

  Serial.print("ok");
  return 1;
}

static uint8_t setup_db_store(uint8_t *buffer) {
  uint8_t cipherkey[THSM_KEY_SIZE * 2];
  uint8_t ciphertext[sizeof(flash_cache.body)];

  /* load cipherkey */
  if (buffer_load_hex(cipherkey, &buffer, sizeof(cipherkey)) != sizeof(cipherkey)) {
    Serial.println("failed to load cipherkey");
    return 0;
  }

  /* check header */
  uint32_t magic = read_uint32(flash_cache.header.magic);
  if (magic != 0xdeadbeef) {
    Serial.println("invalid header");
    return 0;
  }

  /* update cache hash */
  sha1_calculate((uint8_t *)&flash_cache.body, sizeof(flash_cache.body), flash_cache.header.digest);

  /* encrypt body */
  aes_cbc_encrypt(ciphertext, (uint8_t *)&flash_cache.body, sizeof(flash_cache.body), cipherkey, sizeof(cipherkey));
  memcpy((uint8_t *)&flash_cache.body, ciphertext, sizeof(ciphertext));

  /* cleanup temporary variables */
  memset(ciphertext, 0, sizeof(ciphertext));
  memset(cipherkey,  0, sizeof(cipherkey));

  flash_update((uint8_t *)&flash_cache, 0, sizeof(flash_cache));

  Serial.print("ok");
  return 1;
}

static uint8_t setup_db_store_auto(uint8_t *buffer) {
  uint8_t cipherkey[THSM_KEY_SIZE * 2];
  uint8_t ciphertext[sizeof(flash_cache.body)];

  /* check header */
  uint32_t magic = read_uint32(flash_cache.header.magic);
  if (magic != 0xdeadbeef) {
    Serial.println("invalid header");
    return 0;
  }

  /* generate key */
  drbg_read(cipherkey, sizeof(cipherkey));

  /* update cache hash */
  sha1_calculate((uint8_t *)&flash_cache.body, sizeof(flash_cache.body), flash_cache.header.digest);

  /* encrypt body */
  aes_cbc_encrypt(ciphertext, (uint8_t *)&flash_cache.body, sizeof(flash_cache.body), cipherkey, sizeof(cipherkey));
  memcpy((uint8_t *)&flash_cache.body, ciphertext, sizeof(ciphertext));

  flash_update((uint8_t *)&flash_cache, 0, sizeof(flash_cache));

  Serial.print("key : "); hexdump(cipherkey, sizeof(cipherkey), -1);

  /* cleanup temporary variables */
  memset(ciphertext, 0, sizeof(ciphertext));
  memset(cipherkey,  0, sizeof(cipherkey));

  return 1;
}

static uint8_t setup_db_status(uint8_t *buffer) {
  /* check header */
  uint32_t magic = read_uint32(flash_cache.header.magic);
  if (magic != 0xdeadbeef) {
    Serial.println("invalid header");
    return 0;
  }

  /* compare hash */
  if (!sha1_compare((uint8_t *)&flash_cache.body, sizeof(flash_cache.body), flash_cache.header.digest)) {
    Serial.println("hash mismatch");
    return 0;
  }

  Serial.println("key slot  : 00 01 02 03 04 05 06 07 08 09 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31");
  Serial.print  ("available : ");

  for (uint16_t i = 0; i < THSM_DB_KEY_ENTRIES; i++) {
    uint32_t handle = read_uint32(flash_cache.body.keys.entries[i].handle);

    if (handle != 0) {
      Serial.print(" N ");
    } else {
      Serial.print(" Y ");
    }
  }

  Serial.println();
  Serial.println();
  Serial.println("secret slot : 00 01 02 03 04 05 06 07 08 09 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31");
  Serial.print  ("available   : ");

  for (uint16_t i = 0; i < THSM_DB_SECRET_ENTRIES; i++) {
    if (!is_clear_bytes(flash_cache.body.secrets.entries[i].public_id, THSM_PUBLIC_ID_SIZE)) {
      Serial.print(" N ");
    } else {
      Serial.print(" Y ");
    }
  }
  return 1;
}

static uint8_t setup_db_key_show(uint8_t *buffer) {
  /* check header */
  uint32_t magic = read_uint32(flash_cache.header.magic);
  if (magic != 0xdeadbeef) {
    Serial.println("invalid header");
    return 0;
  }

  /* compare hash */
  if (!sha1_compare((uint8_t *)&flash_cache.body, sizeof(flash_cache.body), flash_cache.header.digest)) {
    Serial.println("hash mismatch");
    return 0;
  }

  uint8_t index = 0;
  if (buffer_load_hex(&index, &buffer, sizeof(index)) != sizeof(index)) {
    Serial.println("failed to load key slot number");
    return 0;
  }

  if (index > (THSM_DB_KEY_ENTRIES - 1)) {
    Serial.println("key slot number is out of range");
    return 0;
  }

  Serial.print("slot #"); Serial.println(index, DEC);
  Serial.print("  handle : "); hexdump(flash_cache.body.keys.entries[index].handle, sizeof(flash_cache.body.keys.entries[index].handle), -1);
  Serial.print("  flags  : "); hexdump(flash_cache.body.keys.entries[index].flags,  sizeof(flash_cache.body.keys.entries[index].flags),  -1);
  Serial.print("  key    : "); hexdump(flash_cache.body.keys.entries[index].key,    sizeof(flash_cache.body.keys.entries[index].key),    -1);
  return 1;
}

static uint8_t setup_db_key_delete(uint8_t *buffer) {
  uint8_t index = 0;

  if (buffer_load_hex(&index, &buffer, sizeof(index)) != sizeof(index)) {
    Serial.println("failed to load key slot number");
    return 0;
  }

  if (index > (THSM_DB_KEY_ENTRIES - 1)) {
    Serial.println("key slot number is out of range");
    return 0;
  }

  /* delete key entry */
  memset(&flash_cache.body.keys.entries[index], 0, sizeof(flash_cache.body.keys.entries[index]));

  /* update cache hash */
  sha1_calculate((uint8_t *)&flash_cache.body, sizeof(flash_cache.body), flash_cache.header.digest);

  Serial.print("ok");
  return 1;
}

static uint8_t setup_db_key_generate(uint8_t *buffer) {
  uint8_t index = 0;
  uint8_t handle[sizeof(uint32_t)];
  uint8_t flags [sizeof(uint32_t)];
  uint8_t key[THSM_KEY_SIZE];

  if (buffer_load_hex(&index, &buffer, sizeof(index)) != sizeof(index)) {
    Serial.println("failed to load key slot number");
    return 0;
  }

  if (buffer_load_hex(handle, &buffer, sizeof(handle)) != sizeof(handle)) {
    Serial.println("failed to load key handle");
    return 0;
  }

  if (buffer_load_hex(flags, &buffer, sizeof(flags)) != sizeof(flags)) {
    Serial.println("failed to load key flags");
    return 0;
  }

  if (index > (THSM_DB_KEY_ENTRIES - 1)) {
    Serial.println("key slot number is out of range");
    return 0;
  } else if (read_uint32(handle) == 0xffffffff) {
    Serial.println("invalid key handle");
    return 0;
  }

  /* generate random key */
  drbg_read(key, sizeof(key));

  /* store handle and key */
  memcpy(flash_cache.body.keys.entries[index].handle, handle, sizeof(handle));
  memcpy(flash_cache.body.keys.entries[index].flags,  flags,  sizeof(flags));
  memcpy(flash_cache.body.keys.entries[index].key,    key,    sizeof(key));

  /* update cache hash */
  sha1_calculate((uint8_t *)&flash_cache.body, sizeof(flash_cache.body), flash_cache.header.digest);

  Serial.print("key : "); hexdump(key, sizeof(key), -1);
  return 1;
}

static uint8_t setup_db_key_update(uint8_t *buffer) {
  uint8_t index = 0;
  uint8_t handle [sizeof(uint32_t)];
  uint8_t flags  [sizeof(uint32_t)];
  uint8_t payload[THSM_KEY_SIZE];

  if (buffer_load_hex(&index, &buffer, sizeof(index)) != sizeof(index)) {
    Serial.println("failed to load key slot number");
    return 0;
  }

  if (buffer_load_hex(handle, &buffer, sizeof(handle)) != sizeof(handle)) {
    Serial.println("failed to load key handle");
    return 0;
  }

  if (buffer_load_hex(flags, &buffer, sizeof(flags)) != sizeof(flags)) {
    Serial.println("failed to load key flags");
    return 0;
  }

  if (buffer_load_hex(payload, &buffer, sizeof(payload)) != sizeof(payload)) {
    Serial.println("failed to load key payload");
    return 0;
  }

  if (index > (THSM_DB_KEY_ENTRIES - 1)) {
    Serial.println("key slot number is out of range");
    return 0;
  } else if (read_uint32(handle) == 0xffffffff) {
    Serial.println("invalid key handle");
    return 0;
  }

  /* store handle and key */
  memcpy(flash_cache.body.keys.entries[index].handle, handle,  sizeof(handle));
  memcpy(flash_cache.body.keys.entries[index].handle, flags,   sizeof(flags));
  memcpy(flash_cache.body.keys.entries[index].key,    payload, sizeof(payload));

  /* update cache hash */
  sha1_calculate((uint8_t *)&flash_cache.body, sizeof(flash_cache.body), flash_cache.header.digest);

  Serial.print("ok");
  return 1;
}

static uint8_t setup_db_secret_show(uint8_t *buffer) {
  /* check header */
  uint32_t magic = read_uint32(flash_cache.header.magic);
  if (magic != 0xdeadbeef) {
    Serial.println("invalid header");
    return 0;
  }

  /* compare hash */
  if (!sha1_compare((uint8_t *)&flash_cache.body, sizeof(flash_cache.body), flash_cache.header.digest)) {
    Serial.println("hash mismatch");
    return 0;
  }

  uint8_t index = 0;
  if (buffer_load_hex(&index, &buffer, sizeof(index)) != sizeof(index)) {
    Serial.println("failed to load secret slot number");
    return 0;
  }

  if (index > (THSM_DB_KEY_ENTRIES - 1)) {
    Serial.println("key slot number is out of range");
    return 0;
  }

  Serial.print("slot #"); Serial.println(index, DEC);
  Serial.print("  public_id : "); hexdump(flash_cache.body.secrets.entries[index].public_id, sizeof(flash_cache.body.secrets.entries[index].public_id), -1);
  Serial.print("  secret    : "); hexdump(flash_cache.body.secrets.entries[index].key,       sizeof(flash_cache.body.secrets.entries[index].key),       -1);
  Serial.print("  nonce     : "); hexdump(flash_cache.body.secrets.entries[index].nonce,     sizeof(flash_cache.body.secrets.entries[index].nonce),     -1);
  Serial.print("  counter   : "); hexdump(flash_cache.body.secrets.entries[index].counter,   sizeof(flash_cache.body.secrets.entries[index].counter),   -1);

  return 1;
}

static uint8_t setup_db_secret_delete(uint8_t *buffer) {
  uint8_t index = 0;

  if (buffer_load_hex(&index, &buffer, sizeof(index)) != sizeof(index)) {
    Serial.println("failed to load secret slot number");
    return 0;
  }

  if (index > (THSM_DB_SECRET_ENTRIES - 1)) {
    Serial.println("secret slot number is out of range");
    return 0;
  }

  /* delete key entry */
  memset(&flash_cache.body.secrets.entries[index], 0, sizeof(flash_cache.body.secrets.entries[index]));

  /* update cache hash */
  sha1_calculate((uint8_t *)&flash_cache.body, sizeof(flash_cache.body), flash_cache.header.digest);

  Serial.print("ok");
  return 1;
}

static uint8_t setup_db_secret_generate(uint8_t *buffer) {
  return 0;
}

static uint8_t setup_db_secret_update(uint8_t *buffer) {
  return 0;
}
