// Project : Teensy HSM
// Author  : Edi Permadi
// Repo    : https://github.com/edipermadi/teensy-hsm

//--------------------------------------------------------------------------------------------------
// Board Setup
//--------------------------------------------------------------------------------------------------
// Setup
// Board     : Teensy 3.1/3.2
// USB Type  : Serial
// CPU Speed : 72 MHz


//--------------------------------------------------------------------------------------------------
// Includes
//--------------------------------------------------------------------------------------------------
#include <ADC.h>
#include <EEPROM.h>
#include <FastCRC.h>

//--------------------------------------------------------------------------------------------------
// Commands
//--------------------------------------------------------------------------------------------------
#define THSM_CMD_NULL                      0x00
#define THSM_CMD_AEAD_GENERATE             0x01
#define THSM_CMD_BUFFER_AEAD_GENERATE      0x02
#define THSM_CMD_RANDOM_AEAD_GENERATE      0x03
#define THSM_CMD_AEAD_DECRYPT_CMP          0x04
#define THSM_CMD_DB_AEAD_STORE             0x05
#define THSM_CMD_AEAD_OTP_DECODE           0x06
#define THSM_CMD_DB_OTP_VALIDATE           0x07
#define THSM_CMD_DB_AEAD_STORE2            0x08
#define THSM_CMD_AES_ECB_BLOCK_ENCRYPT     0x0d
#define THSM_CMD_AES_ECB_BLOCK_DECRYPT     0x0e
#define THSM_CMD_AES_ECB_BLOCK_DECRYPT_CMP 0x0f
#define THSM_CMD_HMAC_SHA1_GENERATE        0x10
#define THSM_CMD_TEMP_KEY_LOAD             0x11
#define THSM_CMD_BUFFER_LOAD               0x20
#define THSM_CMD_BUFFER_RANDOM_LOAD        0x21
#define THSM_CMD_NONCE_GET                 0x22
#define THSM_CMD_ECHO                      0x23
#define THSM_CMD_RANDOM_GENERATE           0x24
#define THSM_CMD_RANDOM_RESEED             0x25
#define THSM_CMD_SYSTEM_INFO_QUERY         0x26
#define THSM_CMD_HSM_UNLOCK                0x28
#define THSM_CMD_KEY_STORE_DECRYPT         0x29
#define THSM_CMD_MONITOR_EXIT              0x7f

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------
#define THSM_PROTOCOL_VERSION       1
#define THSM_TEMP_KEY_HANDLE        0xffffffff

//--------------------------------------------------------------------------------------------------
// Sizes
//--------------------------------------------------------------------------------------------------
#define THSM_KEY_HANDLE_SIZE        4
#define THSM_KEY_FLAGS_SIZE         4
#define THSM_OTP_SIZE              16 // Size of OTP
#define THSM_BLOCK_SIZE            16 // Size of block operations
#define THSM_KEY_SIZE              16 // Size of key
#define THSM_MAX_KEY_SIZE          32 // Max size of CCMkey
#define THSM_DATA_BUF_SIZE         64 // Size of internal data buffer
#define THSM_AEAD_NONCE_SIZE        6 // Size of AEAD nonce (excluding size of key handle)
#define THSM_AEAD_MAC_SIZE          8 // Size of AEAD MAC field
#define THSM_CCM_CTR_SIZE           2 // Sizeof of AES CCM counter field
#define THSM_AEAD_MAX_SIZE       (THSM_DATA_BUF_SIZE + THSM_AEAD_MAC_SIZE) // Max size of an AEAD block
#define THSM_SHA1_HASH_SIZE        20 // 160-bit SHA1 hash size
#define THSM_CTR_DRBG_SEED_SIZE    32 // Size of CTR-DRBG entropy
#define THSM_MAX_PKT_SIZE        0x60 // Max size of a packet (excluding command byte)
#define THSM_HMAC_RESET          0x01
#define THSM_HMAC_FINAL          0x02
#define THSM_HMAC_SHA1_TO_BUFFER 0x04
#define THSM_SYSTEM_ID_SIZE        12
#define THSM_PUBLIC_ID_SIZE         6
#define THSM_DB_KEY_ENTRIES        40
#define THSM_DB_SECRET_ENTRIES     32
#define THSM_AEAD_SIZE           (THSM_KEY_SIZE + THSM_PUBLIC_ID_SIZE + THSM_AEAD_MAC_SIZE)
#define THSM_OTP_DELTA_MAX         32 // max difference of OTP delta

//--------------------------------------------------------------------------------------------------
// Flags
//--------------------------------------------------------------------------------------------------
#define THSM_FLAG_RESPONSE            0x80

//--------------------------------------------------------------------------------------------------
// Status Code
//--------------------------------------------------------------------------------------------------
#define THSM_STATUS_OK                 0x80
#define THSM_STATUS_KEY_HANDLE_INVALID 0x81
#define THSM_STATUS_AEAD_INVALID       0x82
#define THSM_STATUS_OTP_INVALID        0x83
#define THSM_STATUS_OTP_REPLAY         0x84
#define THSM_STATUS_ID_DUPLICATE       0x85
#define THSM_STATUS_ID_NOT_FOUND       0x86
#define THSM_STATUS_DB_FULL            0x87
#define THSM_STATUS_MEMORY_ERROR       0x88
#define THSM_STATUS_FUNCTION_DISABLED  0x89
#define THSM_STATUS_KEY_STORAGE_LOCKED 0x8a
#define THSM_STATUS_MISMATCH           0x8b
#define THSM_STATUS_INVALID_PARAMETER  0x8c

//--------------------------------------------------------------------------------------------------
// SHA1 constants
//--------------------------------------------------------------------------------------------------
#define SHA1_DIGEST_SIZE_BITS    160
#define SHA1_DIGEST_SIZE_BYTES   (SHA1_DIGEST_SIZE_BITS / 8)
#define SHA1_DIGEST_SIZE_WORDS   (SHA1_DIGEST_SIZE_BYTES / sizeof(uint32_t))
#define SHA1_BLOCK_SIZE_BITS     512
#define SHA1_BLOCK_SIZE_BYTES    (SHA1_BLOCK_SIZE_BITS / 8)
#define SHA1_BLOCK_SIZE_WORDS    (SHA1_BLOCK_SIZE_BYTES / sizeof(uint32_t))

//--------------------------------------------------------------------------------------------------
// Data Structures
//--------------------------------------------------------------------------------------------------
typedef struct {
  uint8_t value   [THSM_BLOCK_SIZE];
  uint8_t key     [THSM_BLOCK_SIZE];
  uint8_t counter [THSM_CTR_DRBG_SEED_SIZE];
} drbg_ctx_t;

typedef struct
{
  uint8_t bytes[SHA1_BLOCK_SIZE_BYTES];
  uint32_t length;
} sha1_buffer_t;

typedef struct
{
  sha1_buffer_t buffer;
  uint32_t hashes[SHA1_DIGEST_SIZE_WORDS];
  uint32_t words[80];
  uint64_t msg_length;
} sha1_ctx_t;

typedef struct
{
  uint8_t key[SHA1_BLOCK_SIZE_BYTES];
  sha1_ctx_t hash;
} hmac_sha1_ctx_t;

typedef union
{
  uint8_t  bytes[THSM_BLOCK_SIZE];
  uint32_t words[THSM_BLOCK_SIZE / sizeof(uint32_t)];
} aes_state_t;

typedef struct {
  aes_state_t keys[15];
} aes_subkeys_t;

typedef union {
  uint8_t  bytes[sizeof(uint32_t)];
  uint32_t words;
} word_t;

typedef struct {
  uint8_t handle[sizeof(uint32_t)];
  uint8_t flags [sizeof(uint32_t)];
  uint8_t key   [THSM_KEY_SIZE];
} THSM_DB_KEY_ENTRY;

typedef struct {
  uint8_t public_id [THSM_PUBLIC_ID_SIZE];
  uint8_t secret    [THSM_KEY_SIZE + THSM_AEAD_NONCE_SIZE];
} THSM_DB_SECRET_ENTRY;

typedef struct {
  THSM_DB_KEY_ENTRY entries[THSM_DB_KEY_ENTRIES];
} THSM_DB_KEYS;

typedef struct {
  THSM_DB_SECRET_ENTRY entries[THSM_DB_SECRET_ENTRIES];
} THSM_DB_SECRETS;

typedef struct {
  uint8_t value[THSM_AEAD_NONCE_SIZE];
} THSM_FLASH_COUNTER_ENTRY;

typedef struct {
  THSM_FLASH_COUNTER_ENTRY entries[THSM_DB_SECRET_ENTRIES];
} THSM_FLASH_COUNTER;

typedef struct {
  THSM_DB_SECRETS    secrets;
  THSM_DB_KEYS       keys;
  THSM_FLASH_COUNTER counter;
} THSM_FLASH_BODY;

typedef struct {
  uint8_t magic[sizeof(uint32_t)];
  uint8_t digest[SHA1_DIGEST_SIZE_BYTES];
} THSM_FLASH_HEADER;

typedef struct {
  THSM_FLASH_HEADER  header;
  THSM_FLASH_BODY    body;
  uint8_t            cmd_flags;
} THSM_FLASH_STORAGE;

typedef struct {
  uint8_t data_len;
  uint8_t data[THSM_DATA_BUF_SIZE];
} THSM_BUFFER;

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
  uint8_t data_len;
  uint8_t data[THSM_DATA_BUF_SIZE];
} THSM_AEAD_GENERATE_REQ;

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
  uint8_t aead      [THSM_AEAD_SIZE]; // key || nonce || mac
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
  uint8_t version_major;                   // Major version number
  uint8_t version_minor;                   // Minor version number
  uint8_t version_build;                   // Build version number
  uint8_t protocol_version;                // Protocol version number
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
} THSM_AEAD_GENERATE_RESP;

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
  uint8_t  public_id[THSM_PUBLIC_ID_SIZE];
  uint8_t  key_handle[THSM_KEY_HANDLE_SIZE];
  uint8_t  counter_timestamp[THSM_AEAD_NONCE_SIZE]; // uint16_use_ctr | uint8_session_ctr | uint24_timestamp
  uint8_t  status;
} THSM_AEAD_OTP_DECODE_RESP;

typedef struct {
  uint8_t  public_id[THSM_PUBLIC_ID_SIZE];
  uint8_t  counter_timestamp[THSM_AEAD_NONCE_SIZE]; // uint16_use_ctr | uint8_session_ctr | uint24_timestamp
  uint8_t  status;
} THSM_DB_OTP_VALIDATE_RESP;

typedef union
{
  uint8_t                        raw[THSM_MAX_PKT_SIZE];
  THSM_ECHO_REQ                  echo;
  THSM_RANDOM_GENERATE_REQ       random_generate;
  THSM_RANDOM_RESEED_REQ         random_reseed;
  THSM_ECB_BLOCK_ENCRYPT_REQ     ecb_encrypt;
  THSM_ECB_BLOCK_DECRYPT_REQ     ecb_decrypt;
  THSM_ECB_BLOCK_DECRYPT_CMP_REQ ecb_decrypt_cmp;
  THSM_BUFFER_LOAD_REQ           buffer_load;
  THSM_BUFFER_RANDOM_LOAD_REQ    buffer_random_load;
  THSM_HMAC_SHA1_GENERATE_REQ    hmac_sha1_generate;
  THSM_HSM_UNLOCK_REQ            hsm_unlock;
  THSM_KEY_STORE_DECRYPT_REQ     key_store_decrypt;
  THSM_NONCE_GET_REQ             nonce_get;
  THSM_AEAD_GENERATE_REQ         aead_generate;
  THSM_BUFFER_AEAD_GENERATE_REQ  buffer_aead_generate;
  THSM_RANDOM_AEAD_GENERATE_REQ  random_aead_generate;
  THSM_AEAD_DECRYPT_CMP_REQ      aead_decrypt_cmp;
  THSM_TEMP_KEY_LOAD_REQ         temp_key_load;
  THSM_DB_AEAD_STORE_REQ         db_aead_store;
  THSM_DB_AEAD_STORE2_REQ        db_aead_store2;
  THSM_AEAD_OTP_DECODE_REQ       aead_otp_decode;
  THSM_DB_OTP_VALIDATE_REQ       db_otp_validate;
} THSM_PAYLOAD_REQ;

typedef union
{
  uint8_t                         raw[THSM_MAX_PKT_SIZE];
  THSM_ECHO_RESP                  echo;
  THSM_SYSTEM_INFO_RESP           system_info;
  THSM_RANDOM_GENERATE_RESP       random_generate;
  THSM_RANDOM_RESEED_RESP         random_reseed;
  THSM_ECB_BLOCK_ENCRYPT_RESP     ecb_encrypt;
  THSM_ECB_BLOCK_DECRYPT_RESP     ecb_decrypt;
  THSM_ECB_BLOCK_DECRYPT_CMP_RESP ecb_decrypt_cmp;
  THSM_BUFFER_LOAD_RESP           buffer_load;
  THSM_BUFFER_RANDOM_LOAD_RESP    buffer_random_load;
  THSM_HMAC_SHA1_GENERATE_RESP    hmac_sha1_generate;
  THSM_HSM_UNLOCK_RESP            hsm_unlock;
  THSM_KEY_STORE_DECRYPT_RESP     key_store_decrypt;
  THSM_NONCE_GET_RESP             nonce_get;
  THSM_AEAD_GENERATE_RESP         aead_generate;
  THSM_BUFFER_AEAD_GENERATE_RESP  buffer_aead_generate;
  THSM_RANDOM_AEAD_GENERATE_RESP  random_aead_generate;
  THSM_AEAD_DECRYPT_CMP_RESP      aead_decrypt_cmp;
  THSM_TEMP_KEY_LOAD_RESP         temp_key_load;
  THSM_DB_AEAD_STORE_RESP         db_aead_store;
  THSM_DB_AEAD_STORE2_RESP        db_aead_store2;
  THSM_AEAD_OTP_DECODE_RESP       aead_otp_decode;
  THSM_DB_OTP_VALIDATE_RESP       db_otp_validate;
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

//--------------------------------------------------------------------------------------------------
// Global Variables
//--------------------------------------------------------------------------------------------------
static THSM_PKT_REQ    request;
static THSM_PKT_RESP   response;
static THSM_BUFFER     thsm_buffer;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------
void setup() {
  led_init();
  drbg_init();
  parser_init();
  hmac_reset();
  keystore_init();

  memset(&thsm_buffer, 0, sizeof(thsm_buffer));

  /* init nonce pool */
  nonce_pool_init();
}

void loop() {
  parser_run();
}


