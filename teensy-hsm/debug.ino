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
  if (!memcmp(debug_buffer, "aes.ecb.encrypt", 15)) {
    debug_aes_ecb_encrypt(debug_buffer + 15);
  } else if (!memcmp(debug_buffer, "aes.ecb.decrypt", 15)) {
    debug_aes_ecb_decrypt(debug_buffer + 15);
  } else {
    Serial.print("err");
  }
}

static void debug_aes_ecb_encrypt(uint8_t *buffer) {
  uint8_t plaintext [THSM_BLOCK_SIZE];
  uint8_t ciphertext[THSM_BLOCK_SIZE];
  uint8_t cipherkey [THSM_BLOCK_SIZE];

  /* clear buffers */
  memset(plaintext,  0, sizeof(plaintext));
  memset(ciphertext, 0, sizeof(ciphertext));
  memset(cipherkey,  0, sizeof(cipherkey));

  if (!buffer_load_hex(plaintext, &buffer, sizeof(plaintext))) {
    Serial.print("err");
    return;
  }

  if (!buffer_load_hex(cipherkey, &buffer, sizeof(cipherkey))) {
    Serial.print("err");
    return;
  }

  /* perform AES ECB encryption */
  aes_ecb_encrypt(ciphertext, plaintext, cipherkey);
  dump_hex(ciphertext, sizeof(ciphertext));
}

static void debug_aes_ecb_decrypt(uint8_t *buffer) {
  uint8_t plaintext [THSM_BLOCK_SIZE];
  uint8_t ciphertext[THSM_BLOCK_SIZE];
  uint8_t cipherkey [THSM_BLOCK_SIZE];

  /* clear buffers */
  memset(plaintext,  0, sizeof(plaintext));
  memset(ciphertext, 0, sizeof(ciphertext));
  memset(cipherkey,  0, sizeof(cipherkey));

  if (!buffer_load_hex(ciphertext, &buffer, sizeof(plaintext))) {
    Serial.print("err");
    return;
  }

  if (!buffer_load_hex(cipherkey, &buffer, sizeof(cipherkey))) {
    Serial.print("err");
    return;
  }

  /* perform AES ECB decryption */
  aes_ecb_decrypt(plaintext, ciphertext, cipherkey);
  dump_hex(plaintext, sizeof(plaintext));
}
