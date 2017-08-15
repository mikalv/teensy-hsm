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

bool Storage::load(const aes_state_t &key, const aes_state_t &iv) {
    eeprom_buffer_t decrypted;
    MEMCLR(decrypted);

    buffer_t plaintext = buffer_t(decrypted.bytes, sizeof(decrypted.bytes));
    buffer_t ciphertext = buffer_t(eeprom.bytes, sizeof(eeprom.bytes));
    buffer_t mac_key = buffer_t(key.bytes, sizeof(key.bytes));

    /* load and decrypt */
    load_raw();
    AESCBC aes = AESCBC();
    aes.decrypt(plaintext, ciphertext, key, iv);

    /* verify mac */
    SHA1HMAC hmac = SHA1HMAC(mac_key);
    buffer_t hmac_in = buffer_t((uint8_t *)decrypted.layout.storage.body, sizeof(decrypted.layout.storage.body));
    bool match = hmac.compare(hmac_in, decrypted.layout.storage.mac);
    return match;
}

void Storage::store(const aes_state_t &key, const aes_state_t &iv) {
}

int32_t Storage::load_key(key_info_t &key, uint32_t handle) {
}

int32_t Storage::store_key(uint32_t slot, const key_info_t &key) {
}

int32_t Storage::load_secret(secret_info_t &secret, uint32_t key_handle, const ccm_nonce_t &nonce) {
}

int32_t Storage::store_secret(uint32_t slot, const secret_info_t & secret, uint32_t key_handle,
        const ccm_nonce_t &nonce) {
}

void Storage::clear() {
}
void Storage::format() {
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
