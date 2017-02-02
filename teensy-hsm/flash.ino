//==================================================================================================
// Project : Teensy HSM
// Author  : Edi Permadi
// Repo    : https://github.com/edipermadi/teensy-hsm
//
// This file is part of TeensyHSM project containing the implementation of persistent storage
// (EEPROM) related functionality.
//==================================================================================================

#define DEBUG_FLASH 0

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
  if ((offset > 2047) || (length > 2048)) {
    return 0;
  }

  length = ((offset + length) > 2048) ? (2048 - offset) : length;
  uint16_t index = offset;

#if DEBUG_FLASH > 0
  Serial.print("writing (offset/size) : ");
  Serial.print(offset, DEC);
  Serial.print("/");
  Serial.println(length, DEC);

  hexdump(src, length, 64);
#else

  for (; length--; index++) {
    uint8_t val_new = *src++;

    uint8_t val_old = EEPROM.read(index);
    if (val_old != val_new) {
      EEPROM.write(index, val_new);
    }

  }

#endif

  return (index - offset);
}
