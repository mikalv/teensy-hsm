//==================================================================================================
// Project : Teensy HSM
// Author  : Edi Permadi
// Repo    : https://github.com/edipermadi/teensy-hsm
//
// This file is part of TeensyHSM project containing the implementation utility functions.
//==================================================================================================

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------
static uint32_t read_uint32(uint8_t *s) {
  return (s[0] << 24) | (s[1] << 16) | (s[2] << 8) | s[3];
}

static void write_uint32(uint8_t *d, uint32_t v) {
  *d++ = (uint8_t)(v >> 24);
  *d++ = (uint8_t)(v >> 16);
  *d++ = (uint8_t)(v >> 8);
  *d++ = (uint8_t)(v >> 0);
}

static void increment_nonce(uint8_t *value) {
  uint8_t ov = 1;

  value[5] += ov; ov = (value[5] == 0);
  value[4] += ov; ov = (value[4] == 0);
  value[3] += ov; ov = (value[3] == 0);
  value[2] += ov; ov = (value[2] == 0);
  value[1] += ov; ov = (value[1] == 0);
  value[0] += ov; ov = (value[0] == 0);
}

uint16_t buffer_load_hex(uint8_t *dst, uint8_t **src, uint16_t length) {
  uint8_t c, v, parsed;
  uint8_t *ptr = *src;

  /* drop space */
  while (1) {
    c = *ptr;
    if (c == 0) {
      return 0;
    } else if ((c != ' ')) {
      break;
    } else {
      ptr++;
    }
  }

  /* parse hex string */
  parsed = 0;
  while (length-- > 0) {
    v = 0;

    c = *ptr++;
    if ((c >= '0') && (c <= '9')) {
      v |= ((c - 48) << 4);
    } else if ((c >= 'a') && (c <= 'f')) {
      v |= ((c - 87) << 4);
    } else if ((c >= 'A') && (c <= 'F')) {
      v |= ((c - 55) << 4);
    } else {
      *src = ptr;
      return parsed;
    }

    c = *ptr++;
    if ((c >= '0') && (c <= '9')) {
      v |= (c - 48);
    } else if ((c >= 'a') && (c <= 'f')) {
      v |= (c - 87);
    } else if ((c >= 'A') && (c <= 'F')) {
      v |= (c - 55);
    } else {
      *src = ptr;
      return parsed;
    }

    *dst++ = v;
    parsed++;
  }

  /* store pointer */
  *src = ptr;
  return parsed;
}

void hexdump(uint8_t *data, uint16_t data_len, int16_t column) {
  for (uint16_t i = 0; i < data_len; i++) {
    uint8_t value = *data++;
    Serial.print((value >> 4) & 0x0f, HEX);
    Serial.print((value >> 0) & 0x0f, HEX);

    if (column < 1) {
      continue;
    } else if (((i + 1) % column) > 0) {
      Serial.print(" ");
    } else {
      Serial.println("");
    }
  }

  Serial.println("");
}

uint8_t is_clear_bytes(uint8_t *data, uint16_t data_len) {
  while (data_len-- > 0) {
    if (*data != 0) {
      return 0;
    }
  }

  return 1;
}

uint8_t is_clear_words(uint32_t *data, uint16_t data_len) {
  while (data_len-- > 0) {
    if (*data != 0) {
      return 0;
    }
  }

  return 1;
}
