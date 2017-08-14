#ifndef __PDU_H__
#define __PDU_H__

#include <stdint.h>
#include "sizes.h"

typedef struct
{
  uint8_t data_len;
  uint8_t data[THSM_MAX_PKT_SIZE - 1];
} THSM_ECHO_REQ;

typedef struct {
  uint8_t bytes_len;
} THSM_RANDOM_GENERATE_REQ;

typedef struct {
  uint8_t seed[THSM_CTR_DRBG_SEED_SIZE];
} THSM_RANDOM_RESEED_REQ;

typedef struct {
  uint8_t key_handle[THSM_KEY_HANDLE_SIZE];
  uint8_t plaintext[THSM_BLOCK_SIZE];
} THSM_ECB_BLOCK_ENCRYPT_REQ;

typedef struct {
  uint8_t key_handle[THSM_KEY_HANDLE_SIZE];
  uint8_t ciphertext[THSM_BLOCK_SIZE];
} THSM_ECB_BLOCK_DECRYPT_REQ;

typedef struct {
  uint8_t key_handle[THSM_KEY_HANDLE_SIZE];
  uint8_t ciphertext[THSM_BLOCK_SIZE];
  uint8_t plaintext [THSM_BLOCK_SIZE];
} THSM_ECB_BLOCK_DECRYPT_CMP_REQ;

typedef struct {
  uint8_t offset;
  uint8_t data_len;
  uint8_t data[THSM_DATA_BUF_SIZE];
} THSM_BUFFER_LOAD_REQ;

typedef struct {
  uint8_t offset;
  uint8_t length;
} THSM_BUFFER_RANDOM_LOAD_REQ;

typedef struct {
  uint8_t key_handle[THSM_KEY_HANDLE_SIZE];
  uint8_t flags;
  uint8_t data_len;
  uint8_t data[THSM_MAX_PKT_SIZE - 6];
} THSM_HMAC_SHA1_GENERATE_REQ;

typedef struct {
  uint8_t public_id[THSM_PUBLIC_ID_SIZE];
  uint8_t otp[THSM_OTP_SIZE];
} THSM_HSM_UNLOCK_REQ;

typedef struct {
  uint8_t key[THSM_MAX_KEY_SIZE];
} THSM_KEY_STORE_DECRYPT_REQ;

typedef struct {
  uint8_t post_inc[sizeof(uint16_t)];
} THSM_NONCE_GET_REQ;


typedef struct {
  uint8_t nonce[THSM_AEAD_NONCE_SIZE];
  uint8_t key_handle[THSM_KEY_HANDLE_SIZE];
} THSM_BUFFER_AEAD_GENERATE_REQ;

typedef struct {
  uint8_t nonce[THSM_AEAD_NONCE_SIZE];
  uint8_t key_handle[THSM_KEY_HANDLE_SIZE];
  uint8_t random_len;
} THSM_RANDOM_AEAD_GENERATE_REQ;

typedef struct {
  uint8_t nonce[THSM_AEAD_NONCE_SIZE];
  uint8_t key_handle[THSM_KEY_HANDLE_SIZE];
  uint8_t data_len;
  uint8_t data[THSM_MAX_PKT_SIZE - 0x10];
} THSM_AEAD_DECRYPT_CMP_REQ;

typedef struct {
  uint8_t nonce[THSM_AEAD_NONCE_SIZE];
  uint8_t key_handle[THSM_KEY_HANDLE_SIZE];
  uint8_t data_len;
  uint8_t data[THSM_MAX_KEY_SIZE + sizeof(uint32_t) + THSM_AEAD_MAC_SIZE];
} THSM_TEMP_KEY_LOAD_REQ;

typedef struct {
  uint8_t public_id [THSM_PUBLIC_ID_SIZE];
  uint8_t key_handle[THSM_KEY_HANDLE_SIZE];
  uint8_t aead      [THSM_AEAD_SIZE];// key || nonce || mac
} THSM_DB_AEAD_STORE_REQ;

typedef struct {
  uint8_t public_id[THSM_PUBLIC_ID_SIZE];
  uint8_t key_handle[THSM_KEY_HANDLE_SIZE];
  uint8_t aead[THSM_AEAD_SIZE]; // key || nonce || mac
  uint8_t nonce[THSM_AEAD_NONCE_SIZE];
} THSM_DB_AEAD_STORE2_REQ;

typedef struct {
  uint8_t public_id[THSM_PUBLIC_ID_SIZE];
  uint8_t key_handle[THSM_KEY_HANDLE_SIZE];
  uint8_t otp[THSM_OTP_SIZE];
  uint8_t aead[THSM_AEAD_SIZE];
} THSM_AEAD_OTP_DECODE_REQ;


typedef struct {
  uint8_t public_id[THSM_PUBLIC_ID_SIZE];
  uint8_t otp[THSM_OTP_SIZE];
} THSM_DB_OTP_VALIDATE_REQ;

typedef struct
{
  uint8_t data_len;
  uint8_t data[THSM_MAX_PKT_SIZE - 1];
} THSM_ECHO_RESP;

typedef struct
{
  uint8_t version_major;             // Major version number
  uint8_t version_minor;             // Minor version number
  uint8_t version_build;             // Build version number
  uint8_t protocol_version;          // Protocol version number
  uint8_t system_uid[THSM_SYSTEM_ID_SIZE]; // System unique identifier
} THSM_SYSTEM_INFO_RESP;

typedef struct {
  uint8_t bytes_len;
  uint8_t bytes[THSM_MAX_PKT_SIZE - 1];
} THSM_RANDOM_GENERATE_RESP;

typedef struct {
  uint8_t status;
} THSM_RANDOM_RESEED_RESP;

typedef struct {
  uint8_t key_handle[THSM_KEY_HANDLE_SIZE];
  uint8_t ciphertext[THSM_BLOCK_SIZE];
  uint8_t status;
} THSM_ECB_BLOCK_ENCRYPT_RESP;

typedef struct {
  uint8_t key_handle[THSM_KEY_HANDLE_SIZE];
  uint8_t plaintext[THSM_BLOCK_SIZE];
  uint8_t status;
} THSM_ECB_BLOCK_DECRYPT_RESP;

typedef struct {
  uint8_t key_handle[THSM_KEY_HANDLE_SIZE];
  uint8_t status;
} THSM_ECB_BLOCK_DECRYPT_CMP_RESP;

typedef struct {
  uint8_t length;
} THSM_BUFFER_LOAD_RESP;

typedef struct {
  uint8_t length;
} THSM_BUFFER_RANDOM_LOAD_RESP;

typedef struct {
  uint8_t key_handle[THSM_KEY_HANDLE_SIZE];
  uint8_t status;
  uint8_t data_len;
  uint8_t data[THSM_SHA1_HASH_SIZE];
} THSM_HMAC_SHA1_GENERATE_RESP;

typedef struct {
  uint8_t status;
} THSM_HSM_UNLOCK_RESP;

typedef struct {
  uint8_t status;
} THSM_KEY_STORE_DECRYPT_RESP;

typedef struct {
  uint8_t status;
  uint8_t nonce[THSM_AEAD_NONCE_SIZE];
} THSM_NONCE_GET_RESP;

typedef struct {
  uint8_t nonce[THSM_AEAD_NONCE_SIZE];
  uint8_t key_handle[THSM_KEY_HANDLE_SIZE];
  uint8_t status;
  uint8_t data_len;
  uint8_t data[THSM_AEAD_MAX_SIZE];
} THSM_BUFFER_AEAD_GENERATE_RESP;

typedef struct {
  uint8_t nonce[THSM_AEAD_NONCE_SIZE];
  uint8_t key_handle[THSM_KEY_HANDLE_SIZE];
  uint8_t status;
  uint8_t data_len;
  uint8_t data[THSM_AEAD_MAX_SIZE];
} THSM_RANDOM_AEAD_GENERATE_RESP;

typedef struct {
  uint8_t nonce[THSM_AEAD_NONCE_SIZE];
  uint8_t key_handle[THSM_KEY_HANDLE_SIZE];
  uint8_t status;
} THSM_AEAD_DECRYPT_CMP_RESP;

typedef struct {
  uint8_t nonce[THSM_AEAD_NONCE_SIZE];
  uint8_t key_handle[THSM_KEY_HANDLE_SIZE];
  uint8_t status;
} THSM_TEMP_KEY_LOAD_RESP;

typedef struct {
  uint8_t public_id[THSM_PUBLIC_ID_SIZE];
  uint8_t key_handle[THSM_KEY_HANDLE_SIZE];
  uint8_t status;
} THSM_DB_AEAD_STORE_RESP;

typedef struct {
  uint8_t public_id[THSM_PUBLIC_ID_SIZE];
  uint8_t key_handle[THSM_KEY_HANDLE_SIZE];
  uint8_t status;
} THSM_DB_AEAD_STORE2_RESP;

typedef struct {
  uint8_t public_id[THSM_PUBLIC_ID_SIZE];
  uint8_t key_handle[THSM_KEY_HANDLE_SIZE];
  uint8_t counter_timestamp[THSM_AEAD_NONCE_SIZE]; // uint16_use_ctr | uint8_session_ctr | uint24_timestamp
  uint8_t status;
} THSM_AEAD_OTP_DECODE_RESP;

typedef struct {
  uint8_t public_id[THSM_PUBLIC_ID_SIZE];
  uint8_t counter_timestamp[THSM_AEAD_NONCE_SIZE]; // uint16_use_ctr | uint8_session_ctr | uint24_timestamp
  uint8_t status;
} THSM_DB_OTP_VALIDATE_RESP;

typedef union
{
  uint8_t raw[THSM_MAX_PKT_SIZE];
  THSM_ECHO_REQ echo;
  THSM_RANDOM_GENERATE_REQ random_generate;
  THSM_RANDOM_RESEED_REQ random_reseed;
  THSM_ECB_BLOCK_ENCRYPT_REQ ecb_encrypt;
  THSM_ECB_BLOCK_DECRYPT_REQ ecb_decrypt;
  THSM_ECB_BLOCK_DECRYPT_CMP_REQ ecb_decrypt_cmp;
  THSM_BUFFER_LOAD_REQ buffer_load;
  THSM_BUFFER_RANDOM_LOAD_REQ buffer_random_load;
  THSM_HMAC_SHA1_GENERATE_REQ hmac_sha1_generate;
  THSM_HSM_UNLOCK_REQ hsm_unlock;
  THSM_KEY_STORE_DECRYPT_REQ key_store_decrypt;
  THSM_NONCE_GET_REQ nonce_get;
  THSM_AEAD_GENERATE_REQ aead_generate;
  THSM_BUFFER_AEAD_GENERATE_REQ buffer_aead_generate;
  THSM_RANDOM_AEAD_GENERATE_REQ random_aead_generate;
  THSM_AEAD_DECRYPT_CMP_REQ aead_decrypt_cmp;
  THSM_TEMP_KEY_LOAD_REQ temp_key_load;
  THSM_DB_AEAD_STORE_REQ db_aead_store;
  THSM_DB_AEAD_STORE2_REQ db_aead_store2;
  THSM_AEAD_OTP_DECODE_REQ aead_otp_decode;
  THSM_DB_OTP_VALIDATE_REQ db_otp_validate;
} THSM_PAYLOAD_REQ;

typedef union
{
  uint8_t raw[THSM_MAX_PKT_SIZE];
  THSM_ECHO_RESP echo;
  THSM_SYSTEM_INFO_RESP system_info;
  THSM_RANDOM_GENERATE_RESP random_generate;
  THSM_RANDOM_RESEED_RESP random_reseed;
  THSM_ECB_BLOCK_ENCRYPT_RESP ecb_encrypt;
  THSM_ECB_BLOCK_DECRYPT_RESP ecb_decrypt;
  THSM_ECB_BLOCK_DECRYPT_CMP_RESP ecb_decrypt_cmp;
  THSM_BUFFER_LOAD_RESP buffer_load;
  THSM_BUFFER_RANDOM_LOAD_RESP buffer_random_load;
  THSM_HMAC_SHA1_GENERATE_RESP hmac_sha1_generate;
  THSM_HSM_UNLOCK_RESP hsm_unlock;
  THSM_KEY_STORE_DECRYPT_RESP key_store_decrypt;
  THSM_NONCE_GET_RESP nonce_get;
  THSM_AEAD_GENERATE_RESP aead_generate;
  THSM_BUFFER_AEAD_GENERATE_RESP buffer_aead_generate;
  THSM_RANDOM_AEAD_GENERATE_RESP random_aead_generate;
  THSM_AEAD_DECRYPT_CMP_RESP aead_decrypt_cmp;
  THSM_TEMP_KEY_LOAD_RESP temp_key_load;
  THSM_DB_AEAD_STORE_RESP db_aead_store;
  THSM_DB_AEAD_STORE2_RESP db_aead_store2;
  THSM_AEAD_OTP_DECODE_RESP aead_otp_decode;
  THSM_DB_OTP_VALIDATE_RESP db_otp_validate;
} THSM_PAYLOAD_RESP;

typedef struct
{
  uint8_t bcnt;
  uint8_t cmd;
  THSM_PAYLOAD_REQ payload;
} THSM_PKT_REQ;

typedef struct
{
  uint8_t bcnt;
  uint8_t cmd;
  THSM_PAYLOAD_RESP payload;
} THSM_PKT_RESP;

#endif
