//--------------------------------------------------------------------------------------------------
// Helper
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

uint8_t buffer_load_hex(uint8_t *dst, uint8_t **src, uint16_t length) {
  uint8_t c, v;
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
      return 0;
    }

    c = *ptr++;
    if ((c >= '0') && (c <= '9')) {
      v |= (c - 48);
    } else if ((c >= 'a') && (c <= 'f')) {
      v |= (c - 87);
    } else if ((c >= 'A') && (c <= 'F')) {
      v |= (c - 55);
    } else {
      return 0;
    }

    *dst++ = v;
  }

  /* store pointer */
  *src = ptr;
  return 1;
}

void dump_hex(uint8_t *data, uint16_t data_len) {
  while (data_len-- > 0) {
    uint8_t v = *data++;
    Serial.print((v >> 4) & 0x0f, HEX);
    Serial.print((v >> 0) & 0x0f, HEX);
  }
}
