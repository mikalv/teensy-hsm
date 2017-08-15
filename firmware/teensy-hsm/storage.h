#ifndef __STORAGE_H__
#define __STORAGE_H__

#include <stdint.h>
#include "aes-ccm.h"
#include "sha1.h"
#include "hardware.h"

#define STORAGE_KEY_ENTRIES     32
#define STORAGE_SECRET_ENTRIES  31

// AEAD secret
// Size : 30 bytes
typedef struct {
    uint8_t key[AES_KEY_SIZE_BYTES]; // [16] aes-key
    uint8_t uid[AES_CCM_NONCE_SIZE_BYTES]; // [6] private-id
    uint8_t mac[AES_CCM_MAC_SIZE_BYTES]; // [8] cbc-mac of key and uid
} aead_secret_t;

// Storage key entry
// Size : 24
typedef struct {
    uint8_t key_handle[sizeof(uint32_t)]; // [4] key handle
    uint8_t key_flags[sizeof(uint32_t)]; // [4] key_flag
    uint8_t key[AES_KEY_SIZE_BYTES]; // [16] aes-key
} storage_key_t;

// Storage secret entry
// Size: 40
typedef struct {
    uint8_t public_id[AES_CCM_NONCE_SIZE_BYTES]; // [6] public_id of secret
    uint8_t counter[sizeof(uint32_t)]; // [4] secret usage counter
    aead_secret_t secret; // [30]
} storage_secret_t;

// Storage body layout
// Size: 2008
typedef struct {
    storage_key_t keys[STORAGE_KEY_ENTRIES]; // [768] 32 * 24 -> 768
    storage_secret_t secrets[STORAGE_SECRET_ENTRIES]; // [1240] 31 * 40
} storage_body_t;

// Storage layout structure
// Size : 2032
typedef struct {
    uint8_t store_ctr[sizeof(uint32_t)]; // [4] // store counter
    sha1_digest_t mac; // [20] MAC of body
    storage_body_t body; // [2008] storage body
} storage_layout_t;

typedef struct {
    uint8_t restart_ctr[sizeof(uint32_t)]; // [4] plain store counter
    uint8_t prng_seed[12]; // [12] plain PRNG seed
    storage_layout_t storage; // [2032] storage layout
} eeprom_layout_t;

typedef union {
    uint8_t bytes[EEPROM_SIZE_BYTES];
    uint8_t words[EEPROM_SIZE_WORDS];
    eeprom_layout_t layout;
} eeprom_buffer_t;

typedef struct {
    uint32_t handle;
    uint32_t flags;
    uint8_t key[AES_KEY_SIZE_BYTES];
} key_info_t;

typedef struct {
    uint8_t key[AES_KEY_SIZE_BYTES];
    uint8_t uid[AES_CCM_NONCE_SIZE_BYTES];
} secret_info_t;

class Storage {
public:
    Storage();
    bool load(const aes_state_t &key, const aes_state_t &iv);
    void store(const aes_state_t &key, const aes_state_t &iv);
    int32_t load_key(key_info_t &key, uint32_t handle);
    int32_t store_key(uint32_t slot, const key_info_t &key);
    int32_t load_secret(secret_info_t &secret, uint32_t key_handle, const ccm_nonce_t &nonce);
    int32_t store_secret(uint32_t slot, const secret_info_t & secret, uint32_t key_handle, const ccm_nonce_t &nonce);
    void clear();
    void format();

private:
    void load_raw();
    void store_raw();
    eeprom_buffer_t eeprom;
    bool loaded;
    bool decrypted;
};
#endif
