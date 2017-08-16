//==================================================================================================
// Project : Teensy HSM
// Author  : Edi Permadi
// Repo    : https://github.com/edipermadi/teensy-hsm
//
// This file is part of TeensyHSM project containing the implementation of persistent storage
// (EEPROM) related functionality.
//==================================================================================================
#ifdef DEBUG_STORAGE
#include <stdio.h>
#endif

#include "error.h"
#include "storage.h"
#include "aes-cbc.h"
#include "sha1-hmac.h"
#include "macros.h"

Storage::Storage()
{
    storage_decrypted = false;
    secret_unlocked = false;
#ifdef DEBUG_STORAGE
    MEMCLR(nv_storage);
#endif
}

int32_t Storage::load(const aes_state_t &key, const aes_state_t &iv)
{
    /* load EEPROM */
    eeprom_buffer_t eeprom;
    load_from_eeprom(eeprom);

    /* setup pointers */
    uint8_t *ptr_in = (uint8_t *) &eeprom.layout.storage.body;
    uint8_t *ptr_out = (uint8_t *) &storage;
    uint32_t length = sizeof(storage);

    /* setup AES */
    aes_state_t pt, ct;
    AESCBC aes = AESCBC();
    aes.init(key, iv);

    /* setup HMAC */
    SHA1HMAC hmac = SHA1HMAC();
    hmac.init(key.bytes, sizeof(key.bytes));

#ifdef DEBUG_STORAGE
    printf("[DEBUG] decrypting storage\n");
#endif

    /* decipher storage */
    while (length)
    {
        MEMCLR(ct);
        uint32_t step = MIN(length, AES_BLOCK_SIZE_BYTES);
        AES::state_fill(ct, ptr_in);
        aes.decrypt(pt, ct);
        hmac.update(pt.bytes, step);
        memcpy(ptr_out, pt.bytes, step);

        ptr_in += step;
        ptr_out += step;
        length -= step;
    }

    /* verify deciphered storage */
    sha1_digest_t mac;
    hmac.final(mac);

    bool validated = memcmp(mac.bytes, eeprom.layout.storage.mac.bytes, sizeof(mac.bytes)) == 0;
    if (!validated)
    {
#ifdef DEBUG_STORAGE
        printf("[DEBUG] mac verification failed\n");
        printf("[DEBUG] mac actual   : ");

        for(int i=0;i<sizeof(mac.bytes);i++)
        {
            printf("%02x ", mac.bytes[i]);
        }
        putchar('\n');

        printf("[DEBUG] mac expected : ");
        for(int j=0;j<sizeof(mac.bytes);j++)
        {
            printf("%02x ", eeprom.layout.storage.mac.bytes[j]);
        }
        putchar('\n');
#endif

        clear();
        return ERROR_CODE_STORAGE_ENCRYPTED;
    }

    storage_decrypted = true;
    return ERROR_CODE_NONE;
}

int32_t Storage::store(const aes_state_t &key, const aes_state_t &iv)
{
    /* ignore if storage not deciphered yet */
    if (!storage_decrypted)
    {
        return ERROR_CODE_STORAGE_ENCRYPTED;
    }

    eeprom_buffer_t current;
    MEMCLR(current);
    load_from_eeprom(current);

    store(key, iv, current);
    return ERROR_CODE_NONE;
}

int32_t Storage::get_key(key_info_t &key, uint32_t handle)
{
    if (!handle)
    {
        return ERROR_CODE_KEY_NOT_FOUND;
    }

    for (int i = 0; i < STORAGE_KEY_ENTRIES; i++)
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
    for (int i = 0; i < STORAGE_KEY_ENTRIES; i++)
    {
        if (READ32(storage.keys[i].handle) == 0)
        {
#ifdef DEBUG_STORAGE
            printf("[DEBUG] putting key at slot #%d\n", i);
#endif
            WRITE32(storage.keys[i].handle, key.handle)
            WRITE32(storage.keys[i].flags, key.flags);
            memcpy(storage.keys[i].bytes, key.bytes, sizeof(key.bytes));
            return ERROR_CODE_NONE;
        }
    }

    return ERROR_CODE_KEY_SLOT_FULL;
}

int32_t Storage::get_secret(secret_info_t &secret, uint32_t key_handle, const aes_ccm_nonce_t &public_id)
{
    key_info_t key_info;
    int32_t ret = get_key(key_info, key_handle);
    if (ret < 0)
    {
        return ret;
    }

    /* scan for matching secrets */
    for (int i = 0; i < STORAGE_SECRET_ENTRIES; i++)
    {
        if (memcmp(storage.secrets[i].public_id, public_id.bytes, sizeof(public_id.bytes)) == 0)
        {
            uint8_t plaintext[AES_AEAD_SECRET_SIZE_BYTES];
            uint8_t ciphertext[AES_AEAD_SECRET_SIZE_BYTES];
            uint32_t length = AES_AEAD_SECRET_SIZE_BYTES;
            uint8_t *ptr_in = ciphertext;
            uint8_t *ptr_out = plaintext;

            /* initialize buffers */
            MEMCLR(plaintext);
            memcpy(ciphertext, storage.secrets[i].secret.bytes, length);

            AESCCM aes = AESCCM();
            aes_state_t key, pt, ct;
            AES::state_fill(key, key_info.bytes);
            aes.init(key, key_handle, public_id, length);
            while (length)
            {
                uint32_t step = MIN(length, sizeof(ct.bytes));

                MEMCLR(ct);
                memcpy(ct.bytes, ptr_in, step);

                aes.decrypt_update(pt, ct);
                memcpy(ptr_out, pt.bytes, step);

                ptr_in += step;
                ptr_out += step;
                length -= step;
            }

            aes_ccm_mac_t mac;
            memcpy(mac.bytes, storage.secrets[i].secret.mac, sizeof(mac.bytes));
            if (aes.decrypt_final(mac))
            {
                unpack_secret(secret, plaintext);
                return ERROR_CODE_NONE;
            }
            return ERROR_CODE_WRONG_KEY;
        }
    }

    return ERROR_CODE_SECRET_NOT_FOUND;
}

int32_t Storage::put_secret(const secret_info_t &secret, uint32_t key_handle, const aes_ccm_nonce_t &public_id)
{
    uint8_t empty[AES_CCM_NONCE_SIZE_BYTES];
    key_info_t key_info;

    MEMCLR(empty);
    int32_t ret = get_key(key_info, key_handle);
    if (ret < 0)
    {
        return ret;
    }

    /* scan for empty secrets slot */
    for (int i = 0; i < STORAGE_SECRET_ENTRIES; i++)
    {
        if (memcmp(empty, storage.secrets[i].public_id, sizeof(empty)) == 0)
        {
            uint8_t plaintext[AES_AEAD_SECRET_SIZE_BYTES];
            uint8_t ciphertext[AES_AEAD_SECRET_SIZE_BYTES];
            uint32_t length = AES_AEAD_SECRET_SIZE_BYTES;
            uint8_t *ptr_in = plaintext;
            uint8_t *ptr_out = ciphertext;
            pack_secret(plaintext, secret);

            aes_state_t pt, ct, key;
            AES::state_fill(key, key_info.bytes);
            AESCCM aes = AESCCM();
            aes.init(key, key_handle, public_id, length);

            while (length)
            {
                uint32_t step = MIN(length, sizeof(pt.bytes));

                MEMCLR(pt);
                memcpy(pt.bytes, ptr_in, step);

                aes.encrypt_update(ct, pt);
                memcpy(ptr_out, ct.bytes, step);

                ptr_in += step;
                ptr_out += step;
                length -= step;
            }

            aes_ccm_mac_t mac;
            aes.encrypt_final(mac);

            WRITE32(storage.secrets[i].counter, 0);
            memcpy(storage.secrets[i].public_id, public_id.bytes, sizeof(public_id.bytes));
            memcpy(storage.secrets[i].secret.bytes, ciphertext, sizeof(ciphertext));
            memcpy(storage.secrets[i].secret.mac, mac.bytes, sizeof(mac.bytes));

            return ERROR_CODE_NONE;
        }
    }

    return ERROR_CODE_SECRET_SLOT_FULL;
}

void Storage::clear()
{
    storage_decrypted = false;
    secret_unlocked = false;
    MEMCLR(storage);
}

void Storage::format(const aes_state_t &key, const aes_state_t &iv)
{
    eeprom_buffer_t current;
    MEMCLR(current);

    WRITE32(storage.keys[0].flags, 0x01);
    WRITE32(storage.keys[0].bytes, 0x02);
    store(key, iv, current);
    clear();
}

void Storage::load_from_eeprom(eeprom_buffer_t &eeprom)
{
#ifdef DEBUG_STORAGE
    printf("[DEBUG] loading from eeprom\n");
#endif

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
    uint8_t buffer[sizeof(storage_body_t)];
    eeprom_buffer_t eeprom;

    MEMCLR(eeprom);
    memcpy(buffer, &storage, sizeof(buffer));

    /* copy plain values */
    uint32_t store_counter = READ32(current.layout.storage.store_counter) + 1;
    memcpy(eeprom.layout.restart_counter, current.layout.restart_counter, sizeof(current.layout.restart_counter));
    WRITE32(eeprom.layout.storage.store_counter, store_counter);
    memcpy(eeprom.layout.prng_seed, current.layout.prng_seed, sizeof(current.layout.prng_seed));

    /* calculate MAC */
    SHA1HMAC hmac = SHA1HMAC();
    hmac.init(key.bytes, sizeof(key.bytes));

    /* encrypt storage */
    uint8_t *ptr_in = buffer;
    uint8_t *ptr_out = (uint8_t *) &eeprom.layout.storage.body;
    uint32_t length = sizeof(storage);

    /* setup AES */
    aes_state_t pt, ct;
    AESCBC aes = AESCBC();
    aes.init(key, iv);

    /* encipher storage */
    while (length)
    {
        MEMCLR(pt);
        uint32_t step = MIN(length, AES_BLOCK_SIZE_BYTES);
        AES::state_fill(pt, ptr_in);
        aes.encrypt(ct, pt);
        hmac.update(pt.bytes, sizeof(pt.bytes));
        memcpy(ptr_out, ct.bytes, step);

        ptr_in += step;
        ptr_out += step;
        length -= step;
    }

    sha1_digest_t mac;
    hmac.final(mac);
    memcpy(eeprom.layout.storage.mac.bytes, mac.bytes, sizeof(mac.bytes));

    store_to_eeprom(eeprom);
}

#ifdef DEBUG_STORAGE
void Storage::dump_nv()
{
    for (int i = 0; i < sizeof(nv_storage); i++)
    {
        printf("%02x%c", nv_storage[i], ((i + 1) % 32) ? ' ' : '\n');
    }
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
        printf("  bytes  = ");
        for (int j = 0; j < sizeof(storage.keys[i].bytes); j++)
        {
            printf("%02x ", storage.keys[i].bytes[j]);
        }
        putchar('\n');
    }
}
#endif

void Storage::unpack_secret(secret_info_t &out, const uint8_t *secret)
{
    memcpy(out.key, secret, sizeof(out.key));
    secret += sizeof(out.key);
    memcpy(out.uid, secret, sizeof(out.uid));
}

void Storage::pack_secret(uint8_t *out, const secret_info_t &secret)
{
    memcpy(out, secret.key, sizeof(secret.key));
    out += sizeof(secret.key);
    memcpy(out, secret.uid, sizeof(secret.uid));
}
