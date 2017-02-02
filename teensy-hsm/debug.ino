//==================================================================================================
// Project : Teensy HSM
// Author  : Edi Permadi
// Repo    : https://github.com/edipermadi/teensy-hsm
//
// This file is part of TeensyHSM project containing the implementation of debugging console.
//==================================================================================================

//--------------------------------------------------------------------------------------------------
// Global variables
//--------------------------------------------------------------------------------------------------
#if DEBUG_CONSOLE > 0
static uint8_t         debug_buffer[512];
static uint16_t        debug_buffer_len = 0;
static sha1_ctx_t      debug_sha1_ctx;
static hmac_sha1_ctx_t debug_hmac_sha1_ctx;
#endif

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------
#if DEBUG_CONSOLE > 0
void debug_reset() {
  debug_buffer_len = 0;
  memset(debug_buffer, 0, sizeof(debug_buffer));
  Serial.print("\r\n$ ");
}
#endif

#if DEBUG_CONSOLE > 0
void debug_run() {
  /* clear buffer */
  uint8_t tab_ctr = 0;

  debug_reset();

  while (1) {
    if (Serial.available()) {
      uint8_t b = Serial.read();

      tab_ctr = (b == '\t') ? (tab_ctr + 1) : 0;
      if (tab_ctr == '\t') {
        Serial.println("\r\nexit");
        return;
      } else if (b == '\t') {
        continue;
      } else if (b == '\b') {
        if (debug_buffer_len > 0) {
          --debug_buffer_len;
          Serial.print(b, BYTE);
        }
      } else if ((b == '\r') || (b == '\n')) {
        Serial.print("\r\n");

        /* terminate buffer */
        debug_buffer_len = (debug_buffer_len >= sizeof(debug_buffer)) ? (sizeof(debug_buffer) - 1) : debug_buffer_len;
        debug_buffer[debug_buffer_len] = 0;

        debug_dispatch();

        debug_reset();
      } else if (((b >= ' ') || (b <= '~')) && (debug_buffer_len < sizeof(debug_buffer))) {
        Serial.print(b, BYTE);
        debug_buffer[debug_buffer_len++] = b;
      }
    }
  }
}
#endif

#if DEBUG_CONSOLE > 0
static void debug_dispatch() {
  uint8_t ret = 0;
  if (!memcmp(debug_buffer, "aes.128.ecb.encrypt", 19)) {
    ret = debug_aes_ecb_encrypt(debug_buffer + 19, THSM_KEY_SIZE);
  } else if (!memcmp(debug_buffer, "aes.128.ecb.decrypt", 19)) {
    ret = debug_aes_ecb_decrypt(debug_buffer + 19, THSM_KEY_SIZE);
  } else if (!memcmp(debug_buffer, "aes.256.ecb.encrypt", 19)) {
    ret = debug_aes_ecb_encrypt(debug_buffer + 19, (THSM_KEY_SIZE * 2));
  } else if (!memcmp(debug_buffer, "aes.256.ecb.decrypt", 19)) {
    ret = debug_aes_ecb_decrypt(debug_buffer + 19, (THSM_KEY_SIZE * 2));
  } else if (!memcmp(debug_buffer, "aes.ccm.encrypt", 15)) {
    ret = debug_aes_ccm_encrypt(debug_buffer + 15);
  } else if (!memcmp(debug_buffer, "aes.ccm.decrypt", 15)) {
    ret = debug_aes_ccm_decrypt(debug_buffer + 15);
  } else if (!memcmp(debug_buffer, "sha1.init", 9)) {
    ret = debug_sha1_init(debug_buffer + 9);
  } else if (!memcmp(debug_buffer, "sha1.update", 11)) {
    ret = debug_sha1_update(debug_buffer + 11);
  } else if (!memcmp(debug_buffer, "sha1.final", 10)) {
    ret = debug_sha1_final(debug_buffer + 10);
  } else if (!memcmp(debug_buffer, "hmac.sha1.init", 14)) {
    ret = debug_hmac_sha1_init(debug_buffer + 14);
  } else if (!memcmp(debug_buffer, "hmac.sha1.update", 16)) {
    ret = debug_hmac_sha1_update(debug_buffer + 16);
  } else if (!memcmp(debug_buffer, "hmac.sha1.final", 15)) {
    ret = debug_hmac_sha1_final(debug_buffer + 15);
  } else if (!memcmp(debug_buffer, "flash.dump", 10)) {
    ret = debug_flash_dump(debug_buffer + 10);
  } else if (!memcmp(debug_buffer, "buffer.dump", 11)) {
    ret = debug_buffer_dump(debug_buffer + 11);
  } else if (!memcmp(debug_buffer, "random.dump", 11)) {
    ret = debug_random_dump(debug_buffer + 11);
  } else if (!memcmp(debug_buffer, "random.seed", 11)) {
    ret = debug_random_seed(debug_buffer + 11);
  }

  if (!ret) {
    Serial.print("err");
  }
}
#endif

#if DEBUG_CONSOLE > 0
static uint8_t debug_aes_ecb_encrypt(uint8_t *buffer, uint8_t key_length) {
  uint8_t plaintext [THSM_BLOCK_SIZE];
  uint8_t ciphertext[THSM_BLOCK_SIZE];
  uint8_t cipherkey [THSM_KEY_SIZE * 2];

  /* clear buffers */
  memset(plaintext,  0, sizeof(plaintext));
  memset(ciphertext, 0, sizeof(ciphertext));
  memset(cipherkey,  0, sizeof(cipherkey));

  if (buffer_load_hex(plaintext, &buffer, sizeof(plaintext)) != sizeof(plaintext)) {
    return 0;
  }


  if (buffer_load_hex(cipherkey, &buffer, key_length) != key_length) {
    return 0;
  }

  /* perform AES ECB encryption */
  aes_ecb_encrypt(ciphertext, plaintext, cipherkey, key_length);
  hexdump(ciphertext, sizeof(ciphertext), -1);

  return 1;
}
#endif

#if DEBUG_CONSOLE > 0
static uint8_t debug_aes_ecb_decrypt(uint8_t *buffer, uint8_t key_length) {
  uint8_t plaintext [THSM_BLOCK_SIZE];
  uint8_t ciphertext[THSM_BLOCK_SIZE];
  uint8_t cipherkey [THSM_KEY_SIZE * 2];

  /* clear buffers */
  memset(plaintext,  0, sizeof(plaintext));
  memset(ciphertext, 0, sizeof(ciphertext));
  memset(cipherkey,  0, sizeof(cipherkey));

  if (buffer_load_hex(ciphertext, &buffer, sizeof(plaintext)) != sizeof(plaintext)) {
    return 0 ;
  }

  if (buffer_load_hex(cipherkey, &buffer, key_length) != key_length) {
    return 0;
  }

  /* perform AES ECB decryption */
  aes_ecb_decrypt(plaintext, ciphertext, cipherkey, key_length);
  hexdump(plaintext, sizeof(plaintext), -1);

  return 1;
}
#endif

#if DEBUG_CONSOLE > 0
static uint8_t debug_aes_ccm_encrypt(uint8_t *buffer) {
  uint16_t length;
  uint8_t plaintext  [(THSM_BLOCK_SIZE * 4)];
  uint8_t ciphertext [(THSM_BLOCK_SIZE * 4) + THSM_AEAD_MAC_SIZE];
  uint8_t cipherkey  [THSM_BLOCK_SIZE];
  uint8_t key_handle [sizeof(uint32_t)];
  uint8_t nonce      [THSM_AEAD_NONCE_SIZE];

  /* clear buffers */
  memset(plaintext,  0, sizeof(plaintext));
  memset(ciphertext, 0, sizeof(ciphertext));
  memset(cipherkey,  0, sizeof(cipherkey));
  memset(key_handle, 0, sizeof(key_handle));
  memset(nonce,      0, sizeof(nonce));

  /* parse plaintext */
  if ((length = buffer_load_hex(plaintext, &buffer, sizeof(plaintext))) == 0) {
    return 0;
  }

  /* parse cipherkey */
  if (buffer_load_hex(cipherkey, &buffer, sizeof(cipherkey)) != sizeof(cipherkey)) {
    return 0;
  }

  /* parse key handle */
  if (buffer_load_hex(key_handle, &buffer, sizeof(key_handle)) != sizeof(key_handle)) {
    return 0;
  }

  /* parse nonce */
  if (buffer_load_hex(nonce, &buffer, sizeof(nonce)) != sizeof(nonce)) {
    return 0;
  }

  /* perform AES ECB encryption */
  aes128_ccm_encrypt(ciphertext, NULL, plaintext, length, key_handle, cipherkey, nonce);
  hexdump(ciphertext, (length + THSM_AEAD_MAC_SIZE), -1);
  return 1;
}
#endif

#if DEBUG_CONSOLE > 0
static uint8_t debug_aes_ccm_decrypt(uint8_t *buffer) {
  uint16_t parsed;
  uint16_t length;
  uint8_t plaintext  [(THSM_BLOCK_SIZE * 4)];
  uint8_t ciphertext [(THSM_BLOCK_SIZE * 4) + THSM_AEAD_MAC_SIZE];
  uint8_t cipherkey  [THSM_BLOCK_SIZE];
  uint8_t key_handle [sizeof(uint32_t)];
  uint8_t nonce      [THSM_AEAD_NONCE_SIZE];
  uint8_t *mac;

  /* clear buffers */
  memset(plaintext,  0, sizeof(plaintext));
  memset(ciphertext, 0, sizeof(ciphertext));
  memset(cipherkey,  0, sizeof(cipherkey));
  memset(key_handle, 0, sizeof(key_handle));
  memset(nonce,      0, sizeof(nonce));

  /* parse plaintext */
  if ((parsed = buffer_load_hex(ciphertext, &buffer, sizeof(ciphertext))) == 0) {
    return 0;
  }

  if (parsed <= THSM_AEAD_MAC_SIZE) {
    return 0;
  }

  /* get length */
  length = parsed - THSM_AEAD_MAC_SIZE;
  mac    = ciphertext + length;

  /* parse cipherkey */
  if (buffer_load_hex(cipherkey, &buffer, sizeof(cipherkey)) != sizeof(cipherkey)) {
    return 0;
  }

  /* parse key handle */
  if (buffer_load_hex(key_handle, &buffer, sizeof(key_handle)) != sizeof(key_handle)) {
    return 0;
  }

  /* parse nonce */
  if (buffer_load_hex(nonce, &buffer, sizeof(nonce)) != sizeof(nonce)) {
    return 0;
  }

  /* perform AES ECB encryption */
  uint8_t matched = aes128_ccm_decrypt(plaintext, ciphertext, length, key_handle, cipherkey, nonce, mac);
  hexdump(plaintext, length, -1);

  return matched;
}
#endif

#if DEBUG_CONSOLE > 0
static uint8_t debug_sha1_init(uint8_t *buffer) {
  sha1_init(&debug_sha1_ctx);
  Serial.print("ok");
  return 1;
}
#endif

#if DEBUG_CONSOLE > 0
static uint8_t debug_sha1_update(uint8_t *buffer) {
  uint8_t data[64];

  memset(data, 0, sizeof(data));
  uint16_t length = buffer_load_hex(data, &buffer, sizeof(data));
  sha1_update(&debug_sha1_ctx, data, length);
  Serial.print("ok");
  return 1;
}
#endif

#if DEBUG_CONSOLE > 0
static uint8_t debug_sha1_final(uint8_t *buffer) {
  uint8_t digest[SHA1_DIGEST_SIZE_BYTES];
  sha1_final(&debug_sha1_ctx, digest);
  hexdump(digest, sizeof(digest), -1);

  return 1;
}
#endif

#if DEBUG_CONSOLE > 0
static uint8_t debug_hmac_sha1_init(uint8_t *buffer) {
  uint8_t data[64];

  memset(data, 0, sizeof(data));
  uint16_t length = buffer_load_hex(data, &buffer, sizeof(data));

  hmac_sha1_init(&debug_hmac_sha1_ctx, data, length);
  Serial.print("ok");
  return 1;
}
#endif

#if DEBUG_CONSOLE > 0
static uint8_t debug_hmac_sha1_update(uint8_t *buffer) {
  uint8_t data[64];

  memset(data, 0, sizeof(data));
  uint16_t length = buffer_load_hex(data, &buffer, sizeof(data));

  hmac_sha1_update(&debug_hmac_sha1_ctx, data, length);
  Serial.print("ok");
  return 1;
}
#endif

#if DEBUG_CONSOLE > 0
uint8_t debug_hmac_sha1_final(uint8_t *buffer) {
  uint8_t digest[SHA1_DIGEST_SIZE_BYTES];
  hmac_sha1_final(&debug_hmac_sha1_ctx, digest);
  hexdump(digest, sizeof(digest), -1);

  return 1;
}
#endif

#if DEBUG_CONSOLE > 0
static uint8_t debug_flash_dump(uint8_t *buffer) {
  uint8_t data[2048];

  flash_read(data, 0, sizeof(data));

  for (uint16_t i = 0; i < sizeof(data); i++) {
    uint8_t v = data[i];
    Serial.print((v >> 4) & 0x0f, HEX);
    Serial.print((v >> 0) & 0x0f, HEX);
    if (i == 0) {
      /* do nothing */
    } else if (((i + 1) %  32) == 0) {
      Serial.print("\r\n");
    } else if (((i + 1) %  4) == 0) {
      Serial.print(' ');
    }
  }

  return 1;
}
#endif

#if DEBUG_CONSOLE > 0
static uint8_t debug_buffer_dump(uint8_t *buffer) {
  uint16_t length = thsm_buffer.data_len;

  Serial.print("length : ");
  Serial.println(length);
  for (uint16_t i = 0; i < length; i++) {
    uint8_t v = thsm_buffer.data[i];
    Serial.print((v >> 4) & 0x0f, HEX);
    Serial.print((v >> 0) & 0x0f, HEX);
    if (i == 0) {
      /* do nothing */
    } else if (((i + 1) %  32) == 0) {
      Serial.print("\r\n");
    } else if (((i + 1) %  4) == 0) {
      Serial.print(' ');
    }
  }

  return 1;
}
#endif

#if DEBUG_CONSOLE > 0
static uint8_t debug_random_dump(uint8_t *buffer) {
  uint8_t length = 0;
  uint8_t data[256];

  /* parse cipherkey */
  if (buffer_load_hex(&length, &buffer, sizeof(length)) != sizeof(length)) {
    return 0;
  }

  /* return error if reseed required */
  if (!drbg_read(data, length)) {
    return 0;
  }

  hexdump(data, sizeof(data), -1);
  return 1;
}
#endif

#if DEBUG_CONSOLE > 0
static uint8_t debug_random_seed(uint8_t *buffer) {
  uint8_t seed[THSM_CTR_DRBG_SEED_SIZE];

  /* parse cipherkey */
  if (buffer_load_hex(seed, &buffer, sizeof(seed)) != sizeof(seed)) {
    return 0;
  }

  /* reseed DRBG */
  drbg_reseed(seed);
  Serial.print("ok");

  return 1;
}
#endif
