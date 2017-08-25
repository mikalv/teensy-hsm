//==================================================================================================
// Project : Teensy HSM
// Author  : Edi Permadi
// Repo    : https://github.com/edipermadi/teensy-hsm
//
// This file is part of TeensyHSM project containing the implementation of persistent storage
// (EEPROM) related functionality.
//==================================================================================================
#ifdef DEBUG_STORAGE
#include "debug.h"
#endif

#include <string.h>
#include "error.h"
#include "util.h"
#include "storage.h"
#include "aes-cbc.h"
#include "sha1-hmac.h"
#include "macros.h"

Storage::Storage()
{
    clear();
}

Storage::~Storage()
{
    clear();
}

void Storage::init()
{
    clear();
}

bool Storage::load(const aes_state_t &key, const aes_state_t &iv)
{
    /* load EEPROM */
    eeprom_buffer_t eeprom;
    load_from_eeprom(eeprom);

    /* setup pointers */
    uint8_t *ptr_in = (uint8_t *) &eeprom.layout.storage.body;
    uint8_t *ptr_out = (uint8_t *) &storage;
    uint32_t length = sizeof(storage);

    /* setup AES */
    AESCBC aes = AESCBC();
    aes.decrypt(ptr_out, ptr_in, length, key.bytes, iv.bytes);

    /* setup HMAC */
    SHA1HMAC hmac = SHA1HMAC();
    bool matched = hmac.compare(eeprom.layout.storage.mac, ptr_out, length, key.bytes, sizeof(key.bytes));
    if (!matched)
    {
        clear();
        return false;
    }

    AES::state_copy(last_key, key);
    AES::state_copy(last_iv, iv);
    storage_decrypted = true;
    return true;
}

void Storage::store(const aes_state_t &key, const aes_state_t &iv)
{
    if (storage_decrypted)
    {
        eeprom_buffer_t current;
        load_from_eeprom(current);

        store(key, iv, current);
    }
}

int32_t Storage::get_key(key_info_t &key, uint32_t handle)
{
    if (!storage_decrypted)
    {
        return ERROR_CODE_STORAGE_ENCRYPTED;
    }

    for (int i = 0; i < STORAGE_KEY_ENTRIES && handle; i++)
    {
        if (READ32(storage.keys[i].handle) == handle)
        {
            key.handle = handle;
            key.flags = READ32(storage.keys[i].flags);
            memcpy(key.bytes, storage.keys[i].bytes, sizeof(key.bytes));
            return ERROR_CODE_NONE;
        }
    }

    return ERROR_CODE_KEY_NOT_FOUND;
}

int32_t Storage::put_key(const key_info_t &key)
{
    if (!storage_decrypted)
    {
        return ERROR_CODE_STORAGE_ENCRYPTED;
    }

    for (int i = 0; i < STORAGE_KEY_ENTRIES; i++)
    {
        if (READ32(storage.keys[i].handle) == 0)
        {
            WRITE32(storage.keys[i].handle, key.handle)
            WRITE32(storage.keys[i].flags, key.flags);
            memcpy(storage.keys[i].bytes, key.bytes, sizeof(key.bytes));

            store(last_key, last_iv);
            return ERROR_CODE_NONE;
        }
    }

    return ERROR_CODE_KEY_SLOT_FULL;
}

int32_t Storage::get_secret(secret_info_t &secret, const key_info_t &key_info, const aes_ccm_nonce_t &public_id)
{
    if (!storage_decrypted)
    {
        return ERROR_CODE_STORAGE_ENCRYPTED;
    }

    /* scan for matching secrets */
    for (int i = 0; i < STORAGE_SECRET_ENTRIES; i++)
    {
        if (memcmp(storage.secrets[i].public_id, public_id.bytes, sizeof(public_id.bytes)) == 0)
        {
            uint8_t plaintext[AES_AEAD_SECRET_SIZE_BYTES];
            uint8_t ciphertext[AES_AEAD_SECRET_SIZE_BYTES + AES_CCM_MAC_SIZE_BYTES];
            uint32_t length = sizeof(ciphertext);

            /* initialize buffers */
            MEMCLR(plaintext);
            memcpy(ciphertext, storage.secrets[i].secret.bytes, AES_AEAD_SECRET_SIZE_BYTES);
            memcpy(ciphertext + AES_AEAD_SECRET_SIZE_BYTES, storage.secrets[i].secret.mac, AES_CCM_MAC_SIZE_BYTES);

            AESCCM aes = AESCCM();
            if (aes.decrypt(plaintext, ciphertext, length, key_info.handle, key_info.bytes, public_id.bytes))
            {
                Util::unpack_secret(secret, plaintext);
                return ERROR_CODE_NONE;
            }
            return ERROR_CODE_WRONG_KEY;
        }
    }

    return ERROR_CODE_SECRET_NOT_FOUND;
}

int32_t Storage::get_secret(secret_info_t &secret, const aes_ccm_nonce_t &public_id)
{
    if (!storage_decrypted)
    {
        return ERROR_CODE_STORAGE_ENCRYPTED;
    }

    /* scan for matching secrets */
    for (int i = 0; i < STORAGE_SECRET_ENTRIES; i++)
    {
        if (memcmp(storage.secrets[i].public_id, public_id.bytes, sizeof(public_id.bytes)) == 0)
        {
            uint8_t plaintext[AES_AEAD_SECRET_SIZE_BYTES];
            uint8_t ciphertext[AES_AEAD_SECRET_SIZE_BYTES + AES_CCM_MAC_SIZE_BYTES];
            uint32_t length = sizeof(ciphertext);
            key_info_t key_info;

            /* retrieve key based on stored handle */
            uint32_t handle = READ32(storage.secrets[i].handle);
            int32_t ret = get_key(key_info, handle);
            if (ret < 0)
            {
                return ret;
            }

            /* initialize buffers */
            MEMCLR(plaintext);
            memcpy(ciphertext, storage.secrets[i].secret.bytes, AES_AEAD_SECRET_SIZE_BYTES);
            memcpy(ciphertext + AES_AEAD_SECRET_SIZE_BYTES, storage.secrets[i].secret.mac, AES_CCM_MAC_SIZE_BYTES);

            AESCCM aes = AESCCM();
            if (aes.decrypt(plaintext, ciphertext, length, key_info.handle, key_info.bytes, public_id.bytes))
            {
                Util::unpack_secret(secret, plaintext);
                return ERROR_CODE_NONE;
            }
            return ERROR_CODE_WRONG_KEY;
        }
    }

    return ERROR_CODE_SECRET_NOT_FOUND;
}

int32_t Storage::put_secret(const secret_info_t &secret, const key_info_t &key_info, const aes_ccm_nonce_t &public_id)
{
    if (!storage_decrypted)
    {
        return ERROR_CODE_STORAGE_ENCRYPTED;
    }

    /* scan for empty secrets slot */
    for (int i = 0; i < STORAGE_SECRET_ENTRIES; i++)
    {
        if (Util::is_empty(storage.secrets[i].public_id, sizeof(storage.secrets[i].public_id)))
        {
            uint8_t plaintext[AES_AEAD_SECRET_SIZE_BYTES];
            uint8_t ciphertext[AES_AEAD_SECRET_SIZE_BYTES + AES_CCM_MAC_SIZE_BYTES];

            MEMCLR(plaintext);
            MEMCLR(ciphertext);

            AESCCM aes = AESCCM();
            Util::pack_secret(plaintext, secret);
            aes.encrypt(ciphertext, plaintext, AES_AEAD_SECRET_SIZE_BYTES, key_info.handle, key_info.bytes, public_id.bytes);

            WRITE32(storage.secrets[i].counter, 0);
            WRITE32(storage.secrets[i].handle, key_info.handle);
            memcpy(storage.secrets[i].public_id, public_id.bytes, sizeof(public_id.bytes));
            memcpy(storage.secrets[i].secret.bytes, ciphertext, AES_AEAD_SECRET_SIZE_BYTES);
            memcpy(storage.secrets[i].secret.mac, ciphertext + AES_AEAD_SECRET_SIZE_BYTES, AES_CCM_MAC_SIZE_BYTES);

            store(last_key, last_iv);
            return ERROR_CODE_NONE;
        }
    }

    return ERROR_CODE_SECRET_SLOT_FULL;
}

int32_t Storage::check_counter(const aes_ccm_nonce_t &public_id, uint32_t counter)
{
    if (!storage_decrypted)
    {
        return ERROR_CODE_STORAGE_ENCRYPTED;
    }

    for (int i = 0; i < STORAGE_SECRET_ENTRIES; i++)
    {
        if (memcmp(storage.secrets[i].public_id, public_id.bytes, sizeof(public_id.bytes)) == 0)
        {
            uint32_t ref_counter = READ32(storage.secrets[i].counter);
            if (counter < ref_counter)
            {
                return ERROR_CODE_OTP_PLAYBACK;
            }
            else
            {
                WRITE32(storage.secrets[i].counter, counter + 1);
                store(last_key, last_iv);
                return ERROR_CODE_NONE;
            }
        }
    }

    return ERROR_CODE_SECRET_NOT_FOUND;
}

void Storage::clear()
{
    storage_decrypted = false;
    secret_unlocked = false;
    MEMCLR(storage);
    MEMCLR(last_key);
    MEMCLR(last_iv);
}

void Storage::format(const aes_state_t &key, const aes_state_t &iv)
{
    eeprom_buffer_t current;
    MEMCLR(current);

    MEMCLR(storage);
    store(key, iv, current);
    clear();
}

void Storage::load_from_eeprom(eeprom_buffer_t &eeprom)
{
    MEMCLR(eeprom);
    for (int i = 0; i < sizeof(eeprom.bytes); i++)
    {
#ifndef DEBUG_STORAGE
        eeprom.bytes[i] = EEPROM.read(i);
#else
        eeprom.bytes[i] = nv_storage[i];
#endif
    }
}

void Storage::store_to_eeprom(const eeprom_buffer_t &eeprom)
{
    for (int i = 0; i < sizeof(eeprom.bytes); i++)
    {
#ifndef DEBUG_STORAGE
        EEPROM.write(i, eeprom.bytes[i]);
#else
        nv_storage[i] = eeprom.bytes[i];
#endif
    }
}

void Storage::store(const aes_state_t &key, const aes_state_t &iv, const eeprom_buffer_t &current)
{
    eeprom_buffer_t eeprom;

    MEMCLR(eeprom);

    /* copy plain values */
    uint32_t store_counter = READ32(current.layout.storage.body.store_counter) + 1;
    memcpy(eeprom.layout.restart_counter, current.layout.restart_counter, sizeof(current.layout.restart_counter));
    WRITE32(eeprom.layout.storage.body.store_counter, store_counter);
    memcpy(eeprom.layout.prng_seed, current.layout.prng_seed, sizeof(current.layout.prng_seed));

    /* encrypt storage */
    uint8_t *ptr_in = (uint8_t *) &storage;
    uint8_t *ptr_out = (uint8_t *) &eeprom.layout.storage.body;
    uint32_t length = sizeof(storage);

    /* calculate MAC */
    sha1_digest_t mac;
    SHA1HMAC hmac = SHA1HMAC();
    hmac.calculate(mac, ptr_in, length, key.bytes, sizeof(key.bytes));
    memcpy(eeprom.layout.storage.mac.bytes, mac.bytes, sizeof(mac.bytes));

    /* setup AES */
    aes_state_t pt, ct;
    AESCBC aes = AESCBC();
    aes.encrypt(ptr_out, ptr_in, length, key.bytes, iv.bytes);
    store_to_eeprom(eeprom);
}

#ifdef DEBUG_STORAGE
void Storage::dump_nv()
{
    hexdump("nv :\n", nv_storage, sizeof(nv_storage));
}

void Storage::dump_keys()
{
    for (int i = 0; i < STORAGE_KEY_ENTRIES; i++)
    {
        uint32_t handle = READ32(storage.keys[i].handle);
        uint32_t flags = READ32(storage.keys[i].flags);
        printf("key #%d\n", i);
        printf("  handle = 0x%08x\n", handle);
        printf("  flags  = 0x%08x\n", flags);
        hexdump("  bytes  = ", storage.keys[i].bytes, sizeof(storage.keys[i].bytes));
    }
}
#endif
