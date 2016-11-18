//--------------------------------------------------------------------------------------------------
// Global variables
//--------------------------------------------------------------------------------------------------
static uint8_t  debug_buffer[512];
static uint16_t debug_buffer_len = 0;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------
void debug_reset() {
  debug_buffer_len = 0;
  memset(debug_buffer, 0, sizeof(debug_buffer));
  Serial.print("\r\n$ ");
}

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

static void debug_dispatch() {
  uint8_t ret = 0;
  if (!memcmp(debug_buffer, "aes.ecb.encrypt", 15)) {
    ret = debug_aes_ecb_encrypt(debug_buffer + 15);
  } else if (!memcmp(debug_buffer, "aes.ecb.decrypt", 15)) {
    ret = debug_aes_ecb_decrypt(debug_buffer + 15);
  } else if (!memcmp(debug_buffer, "aes.ccm.encrypt", 15)) {
    ret = debug_aes_ccm_encrypt(debug_buffer + 15);
  } else if (!memcmp(debug_buffer, "aes.ccm.decrypt", 15)) {
    ret = debug_aes_ccm_decrypt(debug_buffer + 15);
  }

  if (!ret) {
    Serial.print("err");
  }
}

static uint8_t debug_aes_ecb_encrypt(uint8_t *buffer) {
  uint8_t plaintext [THSM_BLOCK_SIZE];
  uint8_t ciphertext[THSM_BLOCK_SIZE];
  uint8_t cipherkey [THSM_BLOCK_SIZE];

  /* clear buffers */
  memset(plaintext,  0, sizeof(plaintext));
  memset(ciphertext, 0, sizeof(ciphertext));
  memset(cipherkey,  0, sizeof(cipherkey));

  if (buffer_load_hex(plaintext, &buffer, sizeof(plaintext)) != sizeof(plaintext)) {
    return 0;
  }

  if (buffer_load_hex(cipherkey, &buffer, sizeof(cipherkey)) != sizeof(cipherkey)) {
    return 0;
  }

  /* perform AES ECB encryption */
  aes_ecb_encrypt(ciphertext, plaintext, cipherkey);
  dump_hex(ciphertext, sizeof(ciphertext));

  return 1;
}

static uint8_t debug_aes_ecb_decrypt(uint8_t *buffer) {
  uint8_t plaintext [THSM_BLOCK_SIZE];
  uint8_t ciphertext[THSM_BLOCK_SIZE];
  uint8_t cipherkey [THSM_BLOCK_SIZE];

  /* clear buffers */
  memset(plaintext,  0, sizeof(plaintext));
  memset(ciphertext, 0, sizeof(ciphertext));
  memset(cipherkey,  0, sizeof(cipherkey));

  if (buffer_load_hex(ciphertext, &buffer, sizeof(plaintext)) != sizeof(plaintext)) {
    return 0 ;
  }

  if (buffer_load_hex(cipherkey, &buffer, sizeof(cipherkey)) != sizeof(cipherkey)) {
    return 0;
  }

  /* perform AES ECB decryption */
  aes_ecb_decrypt(plaintext, ciphertext, cipherkey);
  dump_hex(plaintext, sizeof(plaintext));

  return 1;
}

static uint8_t debug_aes_ccm_encrypt(uint8_t *buffer) {
  uint16_t parsed;
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
  aes_ccm_encrypt(ciphertext, plaintext, length, key_handle, cipherkey, nonce);
  dump_hex(ciphertext, length + THSM_AEAD_MAC_SIZE);
  return 1;
}

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
  uint8_t matched = aes_ccm_decrypt(plaintext, ciphertext, length, key_handle, cipherkey, nonce, mac);
  dump_hex(plaintext, length);

  return matched;
}
