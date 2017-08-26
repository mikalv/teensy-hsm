#ifndef __COMMANDS_PRIVATE_H__
#define __COMMANDS_PRIVATE_H__

#include <stdint.h>
#include "aes-ccm.h"
#include "commands.h"

//======================================================================================================================
// STRUCTURES
//======================================================================================================================
typedef struct
{
    uint8_t nonce[AES_CCM_NONCE_SIZE_BYTES];
    uint8_t key_handle[sizeof(uint32_t)];
    uint8_t data_len;
    uint8_t data[THSM_DATA_BUF_SIZE];
} THSM_AEAD_GENERATE_REQ;

typedef struct
{
    uint8_t nonce[AES_CCM_NONCE_SIZE_BYTES];
    uint8_t key_handle[sizeof(uint32_t)];
    uint8_t status;
    uint8_t data_len;
    uint8_t data[AES_CCM_MAX_AEAD_SIZE_BYTES];
} THSM_AEAD_GENERATE_RESP;

typedef struct
{
    uint8_t nonce[AES_CCM_NONCE_SIZE_BYTES];
    uint8_t key_handle[sizeof(uint32_t)];
} THSM_BUFFER_AEAD_GENERATE_REQ;

typedef struct
{
    uint8_t nonce[AES_CCM_NONCE_SIZE_BYTES];
    uint8_t key_handle[sizeof(uint32_t)];
    uint8_t status;
    uint8_t data_len;
    uint8_t data[AES_CCM_MAX_AEAD_SIZE_BYTES];
} THSM_BUFFER_AEAD_GENERATE_RESP;

typedef struct
{
    uint8_t nonce[AES_CCM_NONCE_SIZE_BYTES];
    uint8_t key_handle[sizeof(uint32_t)];
    uint8_t random_len;
} THSM_RANDOM_AEAD_GENERATE_REQ;

typedef struct
{
    uint8_t nonce[AES_CCM_NONCE_SIZE_BYTES];
    uint8_t key_handle[sizeof(uint32_t)];
    uint8_t status;
    uint8_t data_len;
    uint8_t data[AES_CCM_MAX_AEAD_SIZE_BYTES];
} THSM_RANDOM_AEAD_GENERATE_RESP;

typedef struct
{
    uint8_t nonce[AES_CCM_NONCE_SIZE_BYTES];
    uint8_t key_handle[sizeof(uint32_t)];
    uint8_t data_len;
    uint8_t data[THSM_MAX_PKT_SIZE - 0x10];
} THSM_AEAD_DECRYPT_CMP_REQ;

typedef struct
{
    uint8_t nonce[AES_CCM_NONCE_SIZE_BYTES];
    uint8_t key_handle[sizeof(uint32_t)];
    uint8_t status;
} THSM_AEAD_DECRYPT_CMP_RESP;

typedef struct
{
    uint8_t public_id[AES_CCM_NONCE_SIZE_BYTES];
    uint8_t key_handle[sizeof(uint32_t)];
    uint8_t aead[AES_CCM_AEAD_SIZE_BYTES]; // key || nonce || mac
} THSM_DB_AEAD_STORE_REQ;

typedef struct
{
    uint8_t public_id[AES_CCM_NONCE_SIZE_BYTES];
    uint8_t key_handle[sizeof(uint32_t)];
    uint8_t status;
} THSM_DB_AEAD_STORE_RESP;

typedef struct
{
    uint8_t public_id[AES_CCM_NONCE_SIZE_BYTES];
    uint8_t key_handle[sizeof(uint32_t)];
    uint8_t otp[THSM_OTP_SIZE];
    uint8_t aead[AES_CCM_AEAD_SIZE_BYTES];  // key || nonce || mac
} THSM_AEAD_OTP_DECODE_REQ;

typedef struct
{
    uint8_t public_id[AES_CCM_NONCE_SIZE_BYTES];
    uint8_t key_handle[sizeof(uint32_t)];
    uint8_t counter_timestamp[AES_CCM_NONCE_SIZE_BYTES]; // uint16_use_ctr | uint8_session_ctr | uint24_timestamp
    uint8_t status;
} THSM_AEAD_OTP_DECODE_RESP;

typedef struct
{
    uint8_t public_id[AES_CCM_NONCE_SIZE_BYTES];
    uint8_t otp[THSM_OTP_SIZE];
} THSM_DB_OTP_VALIDATE_REQ;

typedef struct
{
    uint8_t public_id[AES_CCM_NONCE_SIZE_BYTES];
    uint8_t counter_timestamp[AES_CCM_NONCE_SIZE_BYTES]; // uint16_use_ctr | uint8_session_ctr | uint24_timestamp
    uint8_t status;
} THSM_DB_OTP_VALIDATE_RESP;

typedef struct
{
    uint8_t public_id[AES_CCM_NONCE_SIZE_BYTES];
    uint8_t key_handle[sizeof(uint32_t)];
    uint8_t aead[AES_CCM_AEAD_SIZE_BYTES]; // key || nonce || mac
    uint8_t nonce[AES_CCM_NONCE_SIZE_BYTES];
} THSM_DB_AEAD_STORE2_REQ;

typedef struct
{
    uint8_t public_id[AES_CCM_NONCE_SIZE_BYTES];
    uint8_t key_handle[sizeof(uint32_t)];
    uint8_t status;
} THSM_DB_AEAD_STORE2_RESP;

typedef struct
{
    uint8_t key_handle[sizeof(uint32_t)];
    uint8_t plaintext[THSM_BLOCK_SIZE];
} THSM_AES_ECB_BLOCK_ENCRYPT_REQ;

typedef struct
{
    uint8_t key_handle[sizeof(uint32_t)];
    uint8_t ciphertext[THSM_BLOCK_SIZE];
    uint8_t status;
} THSM_AES_ECB_BLOCK_ENCRYPT_RESP;

typedef struct
{
    uint8_t key_handle[sizeof(uint32_t)];
    uint8_t ciphertext[THSM_BLOCK_SIZE];
} THSM_AES_ECB_BLOCK_DECRYPT_REQ;

typedef struct
{
    uint8_t key_handle[sizeof(uint32_t)];
    uint8_t plaintext[THSM_BLOCK_SIZE];
    uint8_t status;
} THSM_AES_ECB_BLOCK_DECRYPT_RESP;

typedef struct
{
    uint8_t key_handle[sizeof(uint32_t)];
    uint8_t status;
} THSM_AES_ECB_BLOCK_DECRYPT_CMP_RESP;

typedef struct
{
    uint8_t key_handle[sizeof(uint32_t)];
    uint8_t ciphertext[THSM_BLOCK_SIZE];
    uint8_t plaintext[THSM_BLOCK_SIZE];
} THSM_AES_ECB_BLOCK_DECRYPT_CMP_REQ;

typedef struct
{
    uint8_t key_handle[sizeof(uint32_t)];
    uint8_t flags;
    uint8_t data_len;
    uint8_t data[THSM_MAX_PKT_SIZE - 6];
} THSM_HMAC_SHA1_GENERATE_REQ;

typedef struct
{
    uint8_t key_handle[sizeof(uint32_t)];
    uint8_t status;
    uint8_t data_len;
    uint8_t data[THSM_SHA1_HASH_SIZE];
} THSM_HMAC_SHA1_GENERATE_RESP;

typedef struct
{
    uint8_t nonce[AES_CCM_NONCE_SIZE_BYTES];
    uint8_t key_handle[sizeof(uint32_t)];
    uint8_t data_len;
    uint8_t data[THSM_MAX_KEY_SIZE + AES_CCM_MAC_SIZE_BYTES];
} THSM_TEMP_KEY_LOAD_REQ;

typedef struct
{
    uint8_t nonce[AES_CCM_NONCE_SIZE_BYTES];
    uint8_t key_handle[sizeof(uint32_t)];
    uint8_t status;
} THSM_TEMP_KEY_LOAD_RESP;

typedef struct
{
    uint8_t offset;
    uint8_t data_len;
    uint8_t data[THSM_DATA_BUF_SIZE];
} THSM_BUFFER_LOAD_REQ;

typedef struct
{
    uint8_t length;
} THSM_BUFFER_LOAD_RESP;

typedef struct
{
    uint8_t offset;
    uint8_t length;
} THSM_BUFFER_RANDOM_LOAD_REQ;

typedef struct
{
    uint8_t length;
} THSM_BUFFER_RANDOM_LOAD_RESP;

typedef struct
{
    uint8_t post_inc[sizeof(uint16_t)];
} THSM_NONCE_GET_REQ;

typedef struct
{
    uint8_t status;
    uint8_t nonce[AES_CCM_NONCE_SIZE_BYTES];
} THSM_NONCE_GET_RESP;

typedef struct
{
    uint8_t data_len;
    uint8_t data[THSM_MAX_PKT_SIZE - 1];
} THSM_ECHO_REQ;

typedef struct
{
    uint8_t data_len;
    uint8_t data[THSM_MAX_PKT_SIZE - 1];
} THSM_ECHO_RESP;

typedef struct
{
    uint8_t bytes_len;
} THSM_RANDOM_GENERATE_REQ;

typedef struct
{
    uint8_t bytes_len;
    uint8_t bytes[THSM_MAX_PKT_SIZE - 1];
} THSM_RANDOM_GENERATE_RESP;

typedef struct
{
    uint8_t seed[AES_DRBG_SEED_SIZE_BYTES];
} THSM_RANDOM_RESEED_REQ;

typedef struct
{
    uint8_t status;
} THSM_RANDOM_RESEED_RESP;

typedef struct
{
    uint8_t version_major;             // Major version number
    uint8_t version_minor;             // Minor version number
    uint8_t version_build;             // Build version number
    uint8_t protocol_version;             // Protocol version number
    uint8_t system_uid[THSM_SYSTEM_ID_SIZE];             // System unique identifier
} THSM_SYSTEM_INFO_QUERY_RESP;

typedef struct
{
    uint8_t public_id[AES_CCM_NONCE_SIZE_BYTES];
    uint8_t otp[THSM_OTP_SIZE];
} THSM_HSM_UNLOCK_REQ;

typedef struct
{
    uint8_t status;
} THSM_HSM_UNLOCK_RESP;

typedef struct
{
    uint8_t key[THSM_MAX_KEY_SIZE];
} THSM_KEY_STORE_DECRYPT_REQ;

typedef struct
{
    uint8_t status;
} THSM_KEY_STORE_DECRYPT_RESP;

#endif
