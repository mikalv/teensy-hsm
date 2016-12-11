
//--------------------------------------------------------------------------------------------------
// Flash Storage
//--------------------------------------------------------------------------------------------------
uint16_t flash_read(uint8_t *dst, uint16_t offset, uint16_t length) {
  if (offset > 2047) {
    return 0;
  }

  length = ((offset + length) > 2048) ? (2048 - offset) : length;

  uint16_t index = offset;
  for (; length--; index++) {
    *dst++ = EEPROM.read(index);
  }

  return (index - offset);
}

uint16_t flash_update(uint8_t *src, uint16_t offset, uint16_t length) {
  if (offset > 2047) {
    return 0;
  }

  length = ((offset + length) > 2048) ? (2048 - offset) : length;

  uint16_t index = offset;
  for (; length--; index++) {
    uint8_t val_new = *src++;
    uint8_t val_old = EEPROM.read(index);
    if (val_old != val_new) {
      EEPROM.write(index, val_new);
    }
  }

  return (index - offset);
}
