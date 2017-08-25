#ifndef __STORAGE_H__
#define __STORAGE_H__

#include <stdint.h>
#include "aes-ccm.h"
#include "sha1.h"
#include "hardware.h"

#define STORAGE_KEY_ENTRIES     30
#define STORAGE_SECRET_ENTRIES  29
#define AES_AEAD_SECRET_SIZE_BYTES   (AES_KEY_SIZE_BYTES + AES_CCM_NONCE_SIZE_BYTES)

// AEAD secret
// Size : 30 bytes
typedef struct
{
    uint8_t bytes[AES_AEAD_SECRET_SIZE_BYTES]; // [22] aes-key
    uint8_t mac[AES_CCM_MAC_SIZE_BYTES]; // [8] cbc-mac of key and uid
} aead_secret_t;

// Storage key entry
// Size : 24
typedef struct
{
    uint8_t handle[sizeof(uint32_t)]; // [4] key handle
    uint8_t flags[sizeof(uint32_t)]; // [4] key_flag
    uint8_t bytes[AES_KEY_SIZE_BYTES]; // [16] aes-key
} storage_key_t;

// Storage secret entry
// Size: 44
typedef struct
{
    uint8_t public_id[AES_CCM_NONCE_SIZE_BYTES]; // [6] public_id of secret
    uint8_t handle[sizeof(uint32_t)]; // [4] key_handle
    uint8_t counter[sizeof(uint32_t)]; // [4] secret usage counter
    aead_secret_t secret; // [30]
} storage_secret_t;

// Storage body layout
// Size: 2000
typedef struct
{
    uint8_t store_counter[sizeof(uint32_t)]; // [4]
    storage_key_t keys[STORAGE_KEY_ENTRIES]; // [720] 30 * 24 -> 720
    storage_secret_t secrets[STORAGE_SECRET_ENTRIES]; // [1276] 29 * 44 -> 1276
} storage_body_t;

// Storage layout structure
// Size : 2032
typedef struct
{
    sha1_digest_t mac; // [20] MAC of body
    storage_body_t body; // [2000] storage body
    uint8_t padding[12]; // [12] padding
} storage_layout_t;

typedef struct
{
    uint8_t restart_counter[sizeof(uint32_t)]; // [4] plain store counter
    uint8_t prng_seed[12]; // [12] plain PRNG seed
    storage_layout_t storage; // [2032] storage layout
} eeprom_layout_t;

typedef union
{
    uint8_t bytes[EEPROM_SIZE_BYTES];
    uint8_t words[EEPROM_SIZE_WORDS];
    eeprom_layout_t layout;
} eeprom_buffer_t;

typedef struct
{
    uint32_t handle;
    uint32_t flags;
    uint8_t bytes[AES_KEY_SIZE_BYTES];
} key_info_t;

typedef struct
{
    uint8_t key[AES_KEY_SIZE_BYTES];
    uint8_t uid[AES_CCM_NONCE_SIZE_BYTES];
} secret_info_t;

class Storage
{
public:
    Storage();
    ~Storage();
    void init();
    bool load(const aes_state_t &key, const aes_state_t &iv);
    void store(const aes_state_t &key, const aes_state_t &iv);
    int32_t get_key(key_info_t &key, uint32_t key_handle);
    int32_t put_key(const key_info_t &key);
    int32_t get_secret(secret_info_t &secret, const key_info_t &key_info, const aes_ccm_nonce_t &public_id);
    int32_t get_secret(secret_info_t &secret, const aes_ccm_nonce_t &public_id);
    int32_t put_secret(const secret_info_t &secret, const key_info_t &key_info, const aes_ccm_nonce_t &nonce);
    int32_t check_counter(const aes_ccm_nonce_t &public_id, uint32_t counter);
    void clear();
    void format(const aes_state_t &key, const aes_state_t &iv);
#ifdef DEBUG_STORAGE
    void dump_nv();
    void dump_keys();
#endif

private:
    void store(const aes_state_t &key, const aes_state_t &iv, const eeprom_buffer_t & eeprom);
    void load_from_eeprom(eeprom_buffer_t &eeprom);
    void store_to_eeprom(const eeprom_buffer_t &eeprom);
    bool storage_decrypted;
    bool secret_unlocked;
    storage_body_t storage;
    aes_state_t last_key;
    aes_state_t last_iv;

#ifdef DEBUG_STORAGE
    uint8_t nv_storage[EEPROM_SIZE_BYTES];
#endif
};
#endif
