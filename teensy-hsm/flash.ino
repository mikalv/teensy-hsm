
//--------------------------------------------------------------------------------------------------
// Flash Storage
//--------------------------------------------------------------------------------------------------
uint16_t flash_read(uint8_t *dst, uint16_t offset, uint16_t length) {
  if (offset > 2047) {
    return 0;
  }

  uint16_t index  = offset;

  length = ((offset + length) > 2048) ? (2048 - offset) : length;
  while (length--) {
    *dst++ = EEPROM.read(index++);
  }
  return (index - offset);
}
