//==================================================================================================
// Project : Teensy HSM
// Author  : Edi Permadi
// Repo    : https://github.com/edipermadi/teensy-hsm
//
// This file is part of TeensyHSM project containing the implementation of persistent storage
// (EEPROM) related functionality.
//==================================================================================================
#define STORAGE_DEBUG

#include "storage.h"
#include "aes-cbc.h"
#include "sha1-hmac.h"

#ifndef STORAGE_DEBUG
#include <EEPROM.h>
#define NV_WRITE(i,v)   EEPROM.write((i), (v))
#define NV_READ(i)      EEPROM.read((i))
#else
uint8_t nv_storage[EEPROM_SIZE_BYTES];
#define NV_WRITE(i,v)   nv_storage[(i) & EEPROM_SIZE_BYTES] = (v)
#define NV_READ(i)      nv_storage[(i) & EEPROM_SIZE_BYTES]
#endif

Storage::Storage() {
    loaded = false;
    decrypted = false;
    eeprom = eeprom_buffer_t;
}

void Storage::load(aes_state_t &key) {
    aes_state_t iv;
    eeprom_buffer_t decrypted;

    MEMCLR(iv);
    MEMCLR(decrypted);

    buffer_t plaintext = buffer_t(decrypted.bytes, sizeof(decrypted.bytes));
    buffer_t ciphertext = buffer_t(eeprom.bytes, sizeof(eeprom.bytes));
    buffer_t mac_key = buffer_t(key.bytes, sizeof(key.bytes));

    SHA1HMAC hmac = SHA1HMAC(mac_key);
    AESCBC aes = AESCBC();
    load_raw();

    aes.decrypt(plaintext, ciphertext, key, iv);
}

void Storage::store(aes_state_t &key) {
}

void Storage::clear() {
}

void Storage::load_raw() {
    for (int i = 0; i < sizeof(eeprom.bytes); i++) {
        eeprom.bytes[i] = NV_READ(i);
    }
}

void Storage::store_raw() {
    for (int i = 0; i < sizeof(eeprom.bytes); i++) {
        NV_WRITE(i, eeprom.bytes[i]);
    }
}
