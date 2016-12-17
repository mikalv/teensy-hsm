//==================================================================================================
// Project : Teensy HSM
// Author  : Edi Permadi
// Repo    : https://github.com/edipermadi/teensy-hsm
//
// This file is part of TeensyHSM project containing the implementation of setup console
//==================================================================================================

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
  if (!memcmp(debug_buffer, "db.erase", 8)) {
    ret = setup_db_erase(debug_buffer + 8);
  } else if (!memcmp(debug_buffer, "db.init", 7)) {
    ret = setup_db_init(debug_buffer + 7);
  } else if (!memcmp(debug_buffer, "db.load", 7)) {
    ret = setup_db_load(debug_buffer + 7);
  } else if (!memcmp(debug_buffer, "db.store", 8)) {
    ret = setup_db_store(debug_buffer + 8);
  } else if (!memcmp(debug_buffer, "db.status", 9)) {
    ret = setup_db_status(debug_buffer + 9);
  } else if (!memcmp(debug_buffer, "db.key.list", 11)) {
    ret = setup_db_key_list(debug_buffer + 11);
  } else if (!memcmp(debug_buffer, "db.key.delete", 11)) {
    ret = setup_db_key_delete(debug_buffer + 11);
  } else if (!memcmp(debug_buffer, "db.key.generate", 15)) {
    ret = setup_db_key_generate(debug_buffer + 15);
  } else if (!memcmp(debug_buffer, "db.key.update", 13)) {
    ret = setup_db_key_update(debug_buffer + 13);
  } else if (!memcmp(debug_buffer, "db.secret.list", 14)) {
    ret = setup_db_secret_list(debug_buffer + 14);
  } else if (!memcmp(debug_buffer, "db.secret.delete", 16)) {
    ret = setup_db_secret_delete(debug_buffer + 16);
  } else if (!memcmp(debug_buffer, "db.secret.generate", 18)) {
    ret = setup_db_secret_generate(debug_buffer + 18);
  } else if (!memcmp(debug_buffer, "db.secret.update", 16)) {
    ret = setup_db_secret_update(debug_buffer + 16);
  }

  if (!ret) {
    Serial.print("err");
  }
}

static uint8_t setup_db_erase(uint8_t *ptr) {
  return 0;
}

static uint8_t setup_db_init(uint8_t *ptr) {
  return 0;
}

static uint8_t setup_db_load(uint8_t *ptr) {
  return 0;
}

static uint8_t setup_db_store(uint8_t *ptr) {
  return 0;
}

static uint8_t setup_db_status(uint8_t *ptr) {
  return 0;
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
