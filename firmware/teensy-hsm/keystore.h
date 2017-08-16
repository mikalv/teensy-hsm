#ifndef __FLASH_H__
#define __FLASH_H__

#include <stdint.h>
#include "sizes.h"

typedef struct {
        uint8_t handle[sizeof(uint32_t)];
        uint8_t flags [sizeof(uint32_t)];
        uint8_t key   [THSM_KEY_SIZE];
} THSM_DB_KEY_ENTRY;
//
//typedef struct {
//        uint8_t public_id [THSM_PUBLIC_ID_SIZE];
//        uint8_t key       [THSM_KEY_SIZE];
//        uint8_t nonce     [THSM_AEAD_NONCE_SIZE];
//        uint8_t counter   [sizeof(uint32_t)];
//} THSM_DB_SECRET_ENTRY;

typedef struct {
        THSM_DB_KEY_ENTRY entries[THSM_DB_KEY_ENTRIES];
} THSM_DB_KEYS;

typedef struct {
        THSM_DB_SECRET_ENTRY entries[THSM_DB_SECRET_ENTRIES];
} THSM_DB_SECRETS;

typedef struct {
        THSM_DB_SECRETS secrets;
        THSM_DB_KEYS keys;
} THSM_FLASH_BODY;

typedef struct {
        uint8_t magic[sizeof(uint32_t)];
        uint8_t digest[SHA1_DIGEST_SIZE_BYTES];
} THSM_FLASH_HEADER;

typedef struct {
        THSM_FLASH_HEADER header;
        THSM_FLASH_BODY body;
} THSM_FLASH_STORAGE;

//------------------------------------------------------------------------------
// Function Prototypes
//------------------------------------------------------------------------------
void    keystore_init         ();
uint8_t keystore_unlock       (uint8_t *cipherkey);
void    keystore_store_key    (uint32_t handle, uint32_t flags, uint8_t *key);
uint8_t keystore_load_key     (uint8_t *dst_key, uint32_t *dst_flags, uint32_t handle);
uint8_t keystore_store_secret (uint8_t *public_id, uint8_t *key, uint8_t *nonce, uint32_t counter);
uint8_t keystore_load_secret  (uint8_t *key, uint8_t *nonce, uint8_t *public_id);
#endif
