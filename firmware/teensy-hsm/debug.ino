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
  } else {
    Serial.print("ok");
  }
}
#endif

#if DEBUG_CONSOLE > 0
/**
   Perform AES ECB encryption

   @param key_length  determines mode of operation, set to THSM_KEY_SIZE for AES-128 else AES-256
   @param buffer      parameter buffer, containing plaintext and cipherkey in the following format

                      when key_length == THSM_KEY_SIZE
                          128_bit_hex_plaintext 128_bit_hex_cipherkey

                      when key_length != THSM_KEY_SIZE
                          128_bit_hex_plaintext 256_bit_hex_cipherkey
*/
static uint8_t debug_aes_ecb_encrypt(uint8_t *buffer, uint8_t key_length) {
  uint8_t plaintext [THSM_BLOCK_SIZE  ];
  uint8_t ciphertext[THSM_BLOCK_SIZE  ];
  uint8_t cipherkey [THSM_KEY_SIZE * 2];

  /* clear buffers */
  memset(plaintext,  0, sizeof(plaintext ));
  memset(ciphertext, 0, sizeof(ciphertext));
  memset(cipherkey,  0, sizeof(cipherkey ));

  /* load plaintext and ciphertext*/
  if (buffer_load_hex(plaintext, &buffer, sizeof(plaintext)) != sizeof(plaintext)) {
    return 0;
  } else if (buffer_load_hex(cipherkey, &buffer, key_length) != key_length) {
    return 0;
  }

  /* perform AES ECB encryption */
  aes_ecb_encrypt(ciphertext, plaintext, cipherkey, key_length);

  /* dump buffers */
  Serial.print("ck : "); hexdump(cipherkey,  key_length,         -1);
  Serial.print("pt : "); hexdump(plaintext,  sizeof(plaintext),  -1);
  Serial.print("ct : "); hexdump(ciphertext, sizeof(ciphertext), -1);

  /* clear buffers */
  memset(plaintext,  0, sizeof(plaintext ));
  memset(ciphertext, 0, sizeof(ciphertext));
  memset(cipherkey,  0, sizeof(cipherkey ));

  return 1;
}
#endif

#if DEBUG_CONSOLE > 0
/**
   Perform AES ECB decryption

   @param key_length  determines mode of operation, set to THSM_KEY_SIZE for AES-128 else AES-256
   @param buffer      parameter buffer, containing ciphertext and cipherkey in the following format

                      when key_length == THSM_KEY_SIZE
                          128_bit_hex_ciphertext 128_bit_hex_cipherkey

                      when key_length != THSM_KEY_SIZE
                          128_bit_hex_ciphertext 256_bit_hex_cipherkey
*/
static uint8_t debug_aes_ecb_decrypt(uint8_t *buffer, uint8_t key_length) {
  uint8_t plaintext [THSM_BLOCK_SIZE];
  uint8_t ciphertext[THSM_BLOCK_SIZE];
  uint8_t cipherkey [THSM_KEY_SIZE * 2];

  /* clear buffers */
  memset(plaintext,  0, sizeof(plaintext));
  memset(ciphertext, 0, sizeof(ciphertext));
  memset(cipherkey,  0, sizeof(cipherkey));

  /* load ciphertext and cipherkey */
  if (buffer_load_hex(ciphertext, &buffer, sizeof(plaintext)) != sizeof(plaintext)) {
    return 0 ;
  } else if (buffer_load_hex(cipherkey, &buffer, key_length) != key_length) {
    return 0;
  }

  /* perform AES ECB decryption */
  aes_ecb_decrypt(plaintext, ciphertext, cipherkey, key_length);

  /* dump buffers */
  Serial.print("ck : "); hexdump(cipherkey,  key_length,         -1);
  Serial.print("ct : "); hexdump(ciphertext, sizeof(ciphertext), -1);
  Serial.print("pt : "); hexdump(plaintext,  sizeof(plaintext),  -1);

  /* clear buffers */
  memset(plaintext,  0, sizeof(plaintext ));
  memset(ciphertext, 0, sizeof(ciphertext));
  memset(cipherkey,  0, sizeof(cipherkey ));

  return 1;
}
#endif

#if DEBUG_CONSOLE > 0
/**
   Performs AES-128 CCM encryption

   @param buffer  buffer of plaintext, cipherkey, key_handle and nonce
                  - maximum plaintext is 64 bytes
                  - cipherkey is fixed 16 bytes
                  - key_handle is fixed to 4 bytes
                  - nonce is fixed to 6 bytes
*/
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

  /* parse plaintext, ciphertext, key_handle and nonce */
  if ((length = buffer_load_hex(plaintext, &buffer, sizeof(plaintext))) == 0) {
    return 0;
  } else if (buffer_load_hex(cipherkey, &buffer, sizeof(cipherkey)) != sizeof(cipherkey)) {
    return 0;
  } else if (buffer_load_hex(key_handle, &buffer, sizeof(key_handle)) != sizeof(key_handle)) {
    return 0;
  } else if (buffer_load_hex(nonce, &buffer, sizeof(nonce)) != sizeof(nonce)) {
    return 0;
  }

  /* perform AES ECB encryption */
  aes128_ccm_encrypt(ciphertext, NULL, plaintext, length, key_handle, cipherkey, nonce);
  Serial.print("kh : "); hexdump(key_handle, sizeof(key_handle),            -1);
  Serial.print("ck : "); hexdump(cipherkey,  sizeof(cipherkey),             -1);
  Serial.print("iv : "); hexdump(nonce,      sizeof(nonce),                 -1);
  Serial.print("pt : "); hexdump(plaintext,  length,                        -1);
  Serial.print("ct : "); hexdump(ciphertext, (length + THSM_AEAD_MAC_SIZE), -1);

  /* clear buffers */
  memset(plaintext,  0, sizeof(plaintext));
  memset(ciphertext, 0, sizeof(ciphertext));
  memset(cipherkey,  0, sizeof(cipherkey));
  memset(key_handle, 0, sizeof(key_handle));
  memset(nonce,      0, sizeof(nonce));

  return 1;
}
#endif

#if DEBUG_CONSOLE > 0
/**
   Performs AES-128 CCM decryption

   @param buffer  buffer of ciphertext, cipherkey, key_handle and nonce
                  - maximum ciphertext is 64 + 6 bytes
                  - cipherkey is fixed 16 bytes
                  - key_handle is fixed to 4 bytes
                  - nonce is fixed to 6 bytes
*/
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
  } else if (parsed <= THSM_AEAD_MAC_SIZE) {
    return 0;
  }

  /* get length */
  length = parsed - THSM_AEAD_MAC_SIZE;
  mac    = ciphertext + length;

  /* parse cipherkey, key_handle and nonce */
  if (buffer_load_hex(cipherkey, &buffer, sizeof(cipherkey)) != sizeof(cipherkey)) {
    return 0;
  } else if (buffer_load_hex(key_handle, &buffer, sizeof(key_handle)) != sizeof(key_handle)) {
    return 0;
  } else if (buffer_load_hex(nonce, &buffer, sizeof(nonce)) != sizeof(nonce)) {
    return 0;
  }

  /* perform AES ECB encryption */
  uint8_t matched = aes128_ccm_decrypt(plaintext, ciphertext, length, key_handle, cipherkey, nonce, mac);
  Serial.print("kh : "); hexdump(key_handle, sizeof(key_handle),            -1);
  Serial.print("ck : "); hexdump(cipherkey,  sizeof(cipherkey),             -1);
  Serial.print("iv : "); hexdump(nonce,      sizeof(nonce),                 -1);
  Serial.print("ct : "); hexdump(ciphertext, (length + THSM_AEAD_MAC_SIZE), -1);
  Serial.print("pt : "); hexdump(plaintext,  length,                        -1);

  /* clear buffers */
  memset(plaintext,  0, sizeof(plaintext));
  memset(ciphertext, 0, sizeof(ciphertext));
  memset(cipherkey,  0, sizeof(cipherkey));
  memset(key_handle, 0, sizeof(key_handle));
  memset(nonce,      0, sizeof(nonce));

  return matched;
}
#endif

#if DEBUG_CONSOLE > 0
static uint8_t debug_sha1_init(uint8_t *buffer) {
  sha1_init(&debug_sha1_ctx);
  return 1;
}
#endif

#if DEBUG_CONSOLE > 0
static uint8_t debug_sha1_update(uint8_t *buffer) {
  uint8_t data[64];
  uint16_t length;

  /* clear buffer */
  memset(data, 0, sizeof(data));

  /* load data and check context */
  if ((length = buffer_load_hex(data, &buffer, sizeof(data))) < 1) {
    Serial.println("data is empty");
    return 0;
  } else if (is_clear_words(debug_sha1_ctx.hashes, sizeof(debug_sha1_ctx.hashes))) {
    Serial.println("not initialized");
    return 0;
  }

  /* update hash object */
  sha1_update(&debug_sha1_ctx, data, length);

  /* clear buffer */
  memset(data, 0, sizeof(data));

  return 1;
}
#endif

#if DEBUG_CONSOLE > 0
static uint8_t debug_sha1_final(uint8_t *buffer) {
  uint8_t digest[SHA1_DIGEST_SIZE_BYTES];

  /* check if context is initialized */
  if (is_clear_words(debug_sha1_ctx.hashes, sizeof(debug_sha1_ctx.hashes))) {
    Serial.println("not initialized");
    return 0;
  }

  sha1_final(&debug_sha1_ctx, digest);
  Serial.print("hash : "); hexdump(digest, sizeof(digest), -1);

  /* clear buffer and context */
  memset(digest, 0, sizeof(digest));
  memset(&debug_sha1_ctx, 0, sizeof(debug_sha1_ctx));

  return 1;
}
#endif

#if DEBUG_CONSOLE > 0
static uint8_t debug_hmac_sha1_init(uint8_t *buffer) {
  uint16_t length = 0;
  uint8_t data[64];

  memset(data, 0, sizeof(data));
  if ((length = buffer_load_hex(data, &buffer, sizeof(data))) < 1) {
    Serial.println("key is empty");
    return 0;
  }

  hmac_sha1_init(&debug_hmac_sha1_ctx, data, length);
  return 1;
}
#endif

#if DEBUG_CONSOLE > 0
static uint8_t debug_hmac_sha1_update(uint8_t *buffer) {
  uint16_t length = 0;
  uint8_t data[64];

  /* clear buffer */
  memset(data, 0, sizeof(data));

  /* check if HMAC state has been initialized */
  if (is_clear_words(debug_hmac_sha1_ctx.hash.hashes, sizeof(debug_hmac_sha1_ctx.hash.hashes))) {
    Serial.println("not initialized");
    return 0;
  } else if ((length = buffer_load_hex(data, &buffer, sizeof(data))) < 1) {
    Serial.println("data is empty");
  }

  /* update HMAC */
  hmac_sha1_update(&debug_hmac_sha1_ctx, data, length);

  /* clear buffer */
  memset(data, 0, sizeof(data));

  return 1;
}
#endif

#if DEBUG_CONSOLE > 0
uint8_t debug_hmac_sha1_final(uint8_t *buffer) {
  uint8_t digest[SHA1_DIGEST_SIZE_BYTES];

  /* check if HMAC state has been initialized */
  if (is_clear_words(debug_hmac_sha1_ctx.hash.hashes, sizeof(debug_hmac_sha1_ctx.hash.hashes))) {
    Serial.println("not initialized");
    return 0;
  }

  /* clear buffer */
  memset(digest, 0, sizeof(digest));

  /* calculate hmac */
  hmac_sha1_final(&debug_hmac_sha1_ctx, digest);

  Serial.print("hmac : "); hexdump(digest, sizeof(digest), -1);

  /* cleanup digest and state */
  memset(digest,               0, sizeof(digest));
  memset(&debug_hmac_sha1_ctx, 0, sizeof(debug_hmac_sha1_ctx));

  return 1;
}
#endif

#if DEBUG_CONSOLE > 0
static uint8_t debug_flash_dump(uint8_t *buffer) {
  uint8_t data[2048];

  flash_read(data, 0, sizeof(data));

  hexdump(data, sizeof(data), 64);

  return 1;
}
#endif

#if DEBUG_CONSOLE > 0
static uint8_t debug_buffer_dump(uint8_t *buffer) {
  uint16_t length = thsm_buffer.data_len;

  Serial.print("length : "); Serial.println(length);
  hexdump(thsm_buffer.data, sizeof(thsm_buffer.data), length);
  return 1;
}
#endif

#if DEBUG_CONSOLE > 0
/**
   Generate random number (1 256 bytes)

   Syntax:
   $ random.dump xx

   Arguments:
   xx -> count of random bytes in hex
*/
static uint8_t debug_random_dump(uint8_t *buffer) {
  uint8_t length = 0;
  uint8_t data[256];

  /* clear random buffer */
  memset(data, 0, sizeof(data));

  /* parse cipherkey */
  if (buffer_load_hex(&length, &buffer, sizeof(length)) != sizeof(length)) {
    Serial.println("insufficient length");
    return 0;
  } else if (length < 1) {
    Serial.println("insufficient length");
    return 0;
  }

  /* return error if reseed required */
  if (!drbg_read(data, length)) {
    return 0;
  }

  Serial.print("random : "); hexdump(data, length, -1);
  return 1;
}
#endif

#if DEBUG_CONSOLE > 0
static uint8_t debug_random_seed(uint8_t *buffer) {
  uint8_t seed[THSM_CTR_DRBG_SEED_SIZE];

  /* parse cipherkey */
  if (buffer_load_hex(seed, &buffer, sizeof(seed)) != sizeof(seed)) {
    Serial.println("insufficiet seed length");
    return 0;
  }

  /* reseed DRBG */
  drbg_reseed(seed);

  return 1;
}
#endif
