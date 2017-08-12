#ifndef __FLASH_H__
#define __FLASH_H__

#include <stdint.h>
#include "sizes.h"

typedef struct {
  uint8_t handle[sizeof(uint32_t)];
  uint8_t flags [sizeof(uint32_t)];
  uint8_t key   [THSM_KEY_SIZE];
} THSM_DB_KEY_ENTRY;

typedef struct {
  uint8_t public_id [THSM_PUBLIC_ID_SIZE];
  uint8_t key       [THSM_KEY_SIZE];
  uint8_t nonce     [THSM_AEAD_NONCE_SIZE];
  uint8_t counter   [sizeof(uint32_t)];
} THSM_DB_SECRET_ENTRY;

typedef struct {
  THSM_DB_KEY_ENTRY entries[THSM_DB_KEY_ENTRIES];
} THSM_DB_KEYS;

typedef struct {
  THSM_DB_SECRET_ENTRY entries[THSM_DB_SECRET_ENTRIES];
} THSM_DB_SECRETS;

typedef struct {
  THSM_DB_SECRETS    secrets;
  THSM_DB_KEYS       keys;
} THSM_FLASH_BODY;

typedef struct {
  uint8_t magic[sizeof(uint32_t)];
  uint8_t digest[SHA1_DIGEST_SIZE_BYTES];
} THSM_FLASH_HEADER;

typedef struct {
  THSM_FLASH_HEADER  header;
  THSM_FLASH_BODY    body;
} THSM_FLASH_STORAGE;

#endif
