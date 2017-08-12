//==================================================================================================
// Project : Teensy HSM
// Author  : Edi Permadi
// Repo    : https://github.com/edipermadi/teensy-hsm
//
// This file is part of TeensyHSM project containing the implementation of persistent storage
// (EEPROM) related functionality.
//==================================================================================================


#include <EEPROM.h>
#include "storage.h"

Storage::Storage() {}

void Storage::load(uint8_t *key, uint16_t key_length) {
  uint8_t buffer[EEPROM_SIZE];

  for (uint16_t i = 0; i < sizeof(buffer); i++) {
    buffer[i] = EEPROM.read(i);
  }

  AES aes = AES();
  aes.init(key, key_length);
}

void Storage::store(uint8_t *key) {
}


//--------------------------------------------------------------------------------------------------
// EEPROM Storage
//--------------------------------------------------------------------------------------------------
uint16_t storage_read(uint8_t *dst, uint16_t length) {
  uint16_t max = (length > EEPROM_SIZE) ? EEPROM_SIZE : length;
  for (uint16_t i = 0; i < max; i++) {
    *dst++ = EEPROM.read(i);
  }

  return max;
}

uint16_t storage_write(uint8_t *src, uint16_t length) {
  if ((offset > 2047) || (length > 2048)) {
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
