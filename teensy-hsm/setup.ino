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
  } else if (!memcmp(setup_buffer, "db.store", 8)) {
    ret = setup_db_store(setup_buffer + 8);
  } else if (!memcmp(setup_buffer, "db.status", 9)) {
    ret = setup_db_status(setup_buffer + 9);
  } else if (!memcmp(setup_buffer, "db.key.list", 11)) {
    ret = setup_db_key_list(setup_buffer + 11);
  } else if (!memcmp(setup_buffer, "db.key.delete", 11)) {
    ret = setup_db_key_delete(setup_buffer + 11);
  } else if (!memcmp(setup_buffer, "db.key.generate", 15)) {
    ret = setup_db_key_generate(setup_buffer + 15);
  } else if (!memcmp(setup_buffer, "db.key.update", 13)) {
    ret = setup_db_key_update(setup_buffer + 13);
  } else if (!memcmp(setup_buffer, "db.secret.list", 14)) {
    ret = setup_db_secret_list(setup_buffer + 14);
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
  Serial.println("db.status");
  Serial.println("db.key.list");
  Serial.println("db.key.delete");
  Serial.println("db.key.generate");
  Serial.println("db.key.update");
  Serial.println("db.secret.list");
  Serial.println("db.secret.delete");
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
  sha1_ctx_t ctx;
  uint8_t    digest[SHA1_DIGEST_SIZE_BYTES];

  /* set all to 0x00 */
  memset(&flash_cache, 0, sizeof(flash_cache));
  write_uint32(flash_cache.header.magic, 0xdeadbeef);

  /* update cache hash */
  sha1_init(&ctx);
  sha1_update(&ctx, (uint8_t *)&flash_cache.body, sizeof(flash_cache.body));
  sha1_final(&ctx, digest);
  memcpy(flash_cache.header.digest, digest, sizeof(digest));

#if SETUP_DEBUG > 0
  hexdump((uint8_t *)&flash_cache, sizeof(flash_cache), 64);
#endif

  Serial.print("ok");
  return 1;
}

static uint8_t setup_db_load(uint8_t *buffer) {
  uint8_t ret = 0;
  sha1_ctx_t ctx;
  uint8_t cipherkey[THSM_KEY_SIZE * 2];
  uint8_t plaintext[sizeof(flash_cache.body)];
  uint8_t digest[SHA1_DIGEST_SIZE_BYTES];

  /* load cipherkey */
  if (buffer_load_hex(cipherkey, &buffer, sizeof(cipherkey)) != sizeof(cipherkey)) {
    return 0;
  }

  /* read entire flash */
  flash_read((uint8_t *)&flash_cache, 0, sizeof(flash_cache));
  uint32_t magic = read_uint32(flash_cache.header.magic);
  if (magic != 0xdeadbeef) {
    return 0;
  }

  /* decrypt */
  aes_cbc_decrypt(plaintext, (uint8_t *)&flash_cache.body, sizeof(flash_cache.body), cipherkey, sizeof(cipherkey));
  memset(cipherkey, 0, sizeof(cipherkey));

  /* compare hash */
  sha1_init(&ctx);
  sha1_update(&ctx, plaintext, sizeof(plaintext));
  sha1_final(&ctx, digest);

  if (!memcmp(digest, flash_cache.header.digest, sizeof(digest))) {
    memcpy((uint8_t *)&flash_cache.body, plaintext, sizeof(plaintext));

    Serial.print("ok");
    ret = 1;
  }

  /* clear temporary buffer */
  memset(plaintext, 0, sizeof(plaintext));

  return ret;
}

static uint8_t setup_db_store(uint8_t *buffer) {
  sha1_ctx_t ctx;
  uint8_t cipherkey[THSM_KEY_SIZE * 2];
  uint8_t ciphertext[sizeof(flash_cache.body)];

  /* load cipherkey */
  if (buffer_load_hex(cipherkey, &buffer, sizeof(cipherkey)) != sizeof(cipherkey)) {
    return 0;
  }

  /* check header */
  uint32_t magic = read_uint32(flash_cache.header.magic);
  if (magic != 0xdeadbeef) {
    return 0;
  }

  /* update body hash */
  sha1_init(&ctx);
  sha1_update(&ctx, (uint8_t *)&flash_cache.body, sizeof(flash_cache.body));
  sha1_final(&ctx, flash_cache.header.digest);

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

static uint8_t setup_db_status(uint8_t *ptr) {
  /* check header */
  uint32_t magic = read_uint32(flash_cache.header.magic);
  if (magic != 0xdeadbeef) {
    return 0;
  }


}

static uint8_t setup_db_key_list(uint8_t *ptr) {
  return 0;
}

static uint8_t setup_db_key_delete(uint8_t *ptr) {
  return 0;
}

static uint8_t setup_db_key_generate(uint8_t *ptr) {
  return 0;
}

static uint8_t setup_db_key_update(uint8_t *ptr) {
  return 0;
}

static uint8_t setup_db_secret_list(uint8_t *ptr) {
  return 0;
}

static uint8_t setup_db_secret_delete(uint8_t *ptr) {
  return 0;
}

static uint8_t setup_db_secret_generate(uint8_t *ptr) {
  return 0;
}

static uint8_t setup_db_secret_update(uint8_t *ptr) {
  return 0;
}
