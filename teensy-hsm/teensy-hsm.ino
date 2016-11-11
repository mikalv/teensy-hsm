// Project : Teensy HSM
// Author  : Edi Permadi
// Repo    : https://github.com/edipermadi/teensy-hsm

//--------------------------------------------------------------------------------------------------
// Changelog
//--------------------------------------------------------------------------------------------------
// Nov 12, 2016 - wrap AES common operation
//
// Nov 10, 2016 - Added hsm unlock command (dummy command, need to add implementation)
//              - Added keystore decryption command (dummy command, need to add implementation)
//              - Fixed HMAC-SHA1 generation
//              - Added ADC rng based nonce get command
//              - Added aead_generate command (limited to phantom key handle 0xffffffff)
//
// Nov 07, 2016 - Implemented HMAC-SHA1 generation command (limited to phantom key handle 0xffffffff)
//
// Oct 25, 2016 - Implemented ECB decrypt and compare command
//
// Oct 24, 2016 - Whiten ADC noise with CRC32
//
// Oct 23, 2016 - Implemented ECB encryption command (limited to phantom key handle 0xffffffff)
//              - Implemented ECB decryption command (limited to phantom key handle 0xffffffff)
//              - Implemented buffer load command
//              - Implemented buffer random load command
//
// Oct 21, 2016 - Request payload buffer overflow checking
//              - Added random generation command (random taken from ADC noise)
//              - Added random reseed command (dummy response)
//
// Oct 20, 2016 - Fixed echo command
//              - Fixed information query command
//              - Rename YHSM_XX to THSM_XX
//
// Oct 19, 2016 - Added echo command
//              - Added information query command
//

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
#include <FastCRC.h>

//--------------------------------------------------------------------------------------------------
// Hardare Configuration
//--------------------------------------------------------------------------------------------------
#define PIN_LED  13
#define PIN_ADC1 A9
#define PIN_ADC2 A9

//--------------------------------------------------------------------------------------------------
// Commands
//--------------------------------------------------------------------------------------------------
#define THSM_CMD_NULL                      0x00
#define THSM_CMD_AEAD_GENERATE             0x01
#define THSM_CMD_BUFFER_AEAD_GENERATE      0x02
#define THSM_CMD_RANDOM_AEAD_GENERATE      0x03
#define THSM_CMD_AEAD_DECRYPT_CMP          0x04
#define THSM_CMD_DB_YUBIKEY_AEAD_STORE     0x05
#define THSM_CMD_AEAD_YUBIKEY_OTP_DECODE   0x06
#define THSM_CMD_DB_OTP_VALIDATE           0x07
#define THSM_CMD_DB_YUBIKEY_AEAD_STORE2    0x08
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
#define THSM_PUBLIC_ID_SIZE         6 // Size of public id for std OTP validation
#define THSM_OTP_SIZE              16 // Size of OTP
#define THSM_BLOCK_SIZE            16 // Size of block operations
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
#define SYSTEM_ID_SIZE             12
#define UID_SIZE                    6
#define KEY_SIZE                   16

//--------------------------------------------------------------------------------------------------
// Flags
//--------------------------------------------------------------------------------------------------
#define THSM_FLAG_RESPONSE            0x80

//--------------------------------------------------------------------------------------------------
// States
//--------------------------------------------------------------------------------------------------
#define STATE_WAIT_BCNT     0
#define STATE_WAIT_CMD      1
#define STATE_WAIT_PAYLOAD  2

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
// Macros
//--------------------------------------------------------------------------------------------------
#define ROTL_1(x) (((x) << 1) | ((x) >> 31))
#define ROTL_5(x) (((x) << 5) | ((x) >> 27))
#define ROTL_30(x)(((x) << 30) | ((x) >> 2))

//--------------------------------------------------------------------------------------------------
// Data Structures
//--------------------------------------------------------------------------------------------------
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
  aes_state_t keys[11];
} aes_subkeys_t;

typedef union {
  uint8_t  bytes[sizeof(uint32_t)];
  uint32_t words;
} word_t;

typedef struct {
  uint8_t key[KEY_SIZE];
  uint8_t uid[UID_SIZE];
} THSM_SECRETS;

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
  uint8_t key_handle[sizeof(uint32_t)];
  uint8_t plaintext[THSM_BLOCK_SIZE];
} THSM_ECB_BLOCK_ENCRYPT_REQ;

typedef struct {
  uint8_t key_handle[sizeof(uint32_t)];
  uint8_t ciphertext[THSM_BLOCK_SIZE];
} THSM_ECB_BLOCK_DECRYPT_REQ;

typedef struct {
  uint8_t key_handle[sizeof(uint32_t)];
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
  uint8_t key_handle[sizeof(uint32_t)];
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
  uint8_t key_handle[sizeof(uint32_t)];
  uint8_t data_len;
  uint8_t data[THSM_AEAD_MAX_SIZE];
} THSM_AEAD_GENERATE_REQ;

typedef struct
{
  uint8_t data_len;
  uint8_t data[THSM_MAX_PKT_SIZE - 1];
} THSM_ECHO_RESP;

typedef struct
{
  uint8_t version_major;               // Major version number
  uint8_t version_minor;               // Minor version number
  uint8_t version_build;               // Build version number
  uint8_t protocol_version;            // Protocol version number
  uint8_t system_uid[SYSTEM_ID_SIZE];  // System unique identifier
} THSM_SYSTEM_INFO_RESP;

typedef struct {
  uint8_t bytes_len;
  uint8_t bytes[THSM_MAX_PKT_SIZE - 1];
} THSM_RANDOM_GENERATE_RESP;

typedef struct {
  uint8_t status;
} THSM_RANDOM_RESEED_RESP;

typedef struct {
  uint8_t key_handle[sizeof(uint32_t)];
  uint8_t ciphertext[THSM_BLOCK_SIZE];
  uint8_t status;
} THSM_ECB_BLOCK_ENCRYPT_RESP;

typedef struct {
  uint8_t key_handle[sizeof(uint32_t)];
  uint8_t plaintext[THSM_BLOCK_SIZE];
  uint8_t status;
} THSM_ECB_BLOCK_DECRYPT_RESP;

typedef struct {
  uint8_t key_handle[sizeof(uint32_t)];
  uint8_t status;
} THSM_ECB_BLOCK_DECRYPT_CMP_RESP;

typedef struct {
  uint8_t length;
} THSM_BUFFER_LOAD_RESP;

typedef struct {
  uint8_t length;
} THSM_BUFFER_RANDOM_LOAD_RESP;

typedef struct {
  uint8_t key_handle[sizeof(uint32_t)];
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
  uint8_t key_handle[sizeof(uint32_t)];
  uint8_t status;
  uint8_t data_len;
  uint8_t data[THSM_AEAD_MAX_SIZE];
} THSM_AEAD_GENERATE_RESP;

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
// Lookup Tables
//--------------------------------------------------------------------------------------------------
static const uint8_t te[256] =   {
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

static const uint8_t td[256] =
{ 0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
  0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
  0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
  0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
  0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
  0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
  0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
  0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
  0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
  0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
  0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
  0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
  0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
  0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
  0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
  0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

static const uint32_t te0[256] = {
  0xa56363c6, 0x847c7cf8, 0x997777ee, 0x8d7b7bf6, 0x0df2f2ff, 0xbd6b6bd6, 0xb16f6fde, 0x54c5c591,
  0x50303060, 0x03010102, 0xa96767ce, 0x7d2b2b56, 0x19fefee7, 0x62d7d7b5, 0xe6abab4d, 0x9a7676ec,
  0x45caca8f, 0x9d82821f, 0x40c9c989, 0x877d7dfa, 0x15fafaef, 0xeb5959b2, 0xc947478e, 0x0bf0f0fb,
  0xecadad41, 0x67d4d4b3, 0xfda2a25f, 0xeaafaf45, 0xbf9c9c23, 0xf7a4a453, 0x967272e4, 0x5bc0c09b,
  0xc2b7b775, 0x1cfdfde1, 0xae93933d, 0x6a26264c, 0x5a36366c, 0x413f3f7e, 0x02f7f7f5, 0x4fcccc83,
  0x5c343468, 0xf4a5a551, 0x34e5e5d1, 0x08f1f1f9, 0x937171e2, 0x73d8d8ab, 0x53313162, 0x3f15152a,
  0x0c040408, 0x52c7c795, 0x65232346, 0x5ec3c39d, 0x28181830, 0xa1969637, 0x0f05050a, 0xb59a9a2f,
  0x0907070e, 0x36121224, 0x9b80801b, 0x3de2e2df, 0x26ebebcd, 0x6927274e, 0xcdb2b27f, 0x9f7575ea,
  0x1b090912, 0x9e83831d, 0x742c2c58, 0x2e1a1a34, 0x2d1b1b36, 0xb26e6edc, 0xee5a5ab4, 0xfba0a05b,
  0xf65252a4, 0x4d3b3b76, 0x61d6d6b7, 0xceb3b37d, 0x7b292952, 0x3ee3e3dd, 0x712f2f5e, 0x97848413,
  0xf55353a6, 0x68d1d1b9, 0x00000000, 0x2cededc1, 0x60202040, 0x1ffcfce3, 0xc8b1b179, 0xed5b5bb6,
  0xbe6a6ad4, 0x46cbcb8d, 0xd9bebe67, 0x4b393972, 0xde4a4a94, 0xd44c4c98, 0xe85858b0, 0x4acfcf85,
  0x6bd0d0bb, 0x2aefefc5, 0xe5aaaa4f, 0x16fbfbed, 0xc5434386, 0xd74d4d9a, 0x55333366, 0x94858511,
  0xcf45458a, 0x10f9f9e9, 0x06020204, 0x817f7ffe, 0xf05050a0, 0x443c3c78, 0xba9f9f25, 0xe3a8a84b,
  0xf35151a2, 0xfea3a35d, 0xc0404080, 0x8a8f8f05, 0xad92923f, 0xbc9d9d21, 0x48383870, 0x04f5f5f1,
  0xdfbcbc63, 0xc1b6b677, 0x75dadaaf, 0x63212142, 0x30101020, 0x1affffe5, 0x0ef3f3fd, 0x6dd2d2bf,
  0x4ccdcd81, 0x140c0c18, 0x35131326, 0x2fececc3, 0xe15f5fbe, 0xa2979735, 0xcc444488, 0x3917172e,
  0x57c4c493, 0xf2a7a755, 0x827e7efc, 0x473d3d7a, 0xac6464c8, 0xe75d5dba, 0x2b191932, 0x957373e6,
  0xa06060c0, 0x98818119, 0xd14f4f9e, 0x7fdcdca3, 0x66222244, 0x7e2a2a54, 0xab90903b, 0x8388880b,
  0xca46468c, 0x29eeeec7, 0xd3b8b86b, 0x3c141428, 0x79dedea7, 0xe25e5ebc, 0x1d0b0b16, 0x76dbdbad,
  0x3be0e0db, 0x56323264, 0x4e3a3a74, 0x1e0a0a14, 0xdb494992, 0x0a06060c, 0x6c242448, 0xe45c5cb8,
  0x5dc2c29f, 0x6ed3d3bd, 0xefacac43, 0xa66262c4, 0xa8919139, 0xa4959531, 0x37e4e4d3, 0x8b7979f2,
  0x32e7e7d5, 0x43c8c88b, 0x5937376e, 0xb76d6dda, 0x8c8d8d01, 0x64d5d5b1, 0xd24e4e9c, 0xe0a9a949,
  0xb46c6cd8, 0xfa5656ac, 0x07f4f4f3, 0x25eaeacf, 0xaf6565ca, 0x8e7a7af4, 0xe9aeae47, 0x18080810,
  0xd5baba6f, 0x887878f0, 0x6f25254a, 0x722e2e5c, 0x241c1c38, 0xf1a6a657, 0xc7b4b473, 0x51c6c697,
  0x23e8e8cb, 0x7cdddda1, 0x9c7474e8, 0x211f1f3e, 0xdd4b4b96, 0xdcbdbd61, 0x868b8b0d, 0x858a8a0f,
  0x907070e0, 0x423e3e7c, 0xc4b5b571, 0xaa6666cc, 0xd8484890, 0x05030306, 0x01f6f6f7, 0x120e0e1c,
  0xa36161c2, 0x5f35356a, 0xf95757ae, 0xd0b9b969, 0x91868617, 0x58c1c199, 0x271d1d3a, 0xb99e9e27,
  0x38e1e1d9, 0x13f8f8eb, 0xb398982b, 0x33111122, 0xbb6969d2, 0x70d9d9a9, 0x898e8e07, 0xa7949433,
  0xb69b9b2d, 0x221e1e3c, 0x92878715, 0x20e9e9c9, 0x49cece87, 0xff5555aa, 0x78282850, 0x7adfdfa5,
  0x8f8c8c03, 0xf8a1a159, 0x80898909, 0x170d0d1a, 0xdabfbf65, 0x31e6e6d7, 0xc6424284, 0xb86868d0,
  0xc3414182, 0xb0999929, 0x772d2d5a, 0x110f0f1e, 0xcbb0b07b, 0xfc5454a8, 0xd6bbbb6d, 0x3a16162c
};

static const uint32_t te1[256] = {
  0x6363c6a5, 0x7c7cf884, 0x7777ee99, 0x7b7bf68d, 0xf2f2ff0d, 0x6b6bd6bd, 0x6f6fdeb1, 0xc5c59154,
  0x30306050, 0x01010203, 0x6767cea9, 0x2b2b567d, 0xfefee719, 0xd7d7b562, 0xabab4de6, 0x7676ec9a,
  0xcaca8f45, 0x82821f9d, 0xc9c98940, 0x7d7dfa87, 0xfafaef15, 0x5959b2eb, 0x47478ec9, 0xf0f0fb0b,
  0xadad41ec, 0xd4d4b367, 0xa2a25ffd, 0xafaf45ea, 0x9c9c23bf, 0xa4a453f7, 0x7272e496, 0xc0c09b5b,
  0xb7b775c2, 0xfdfde11c, 0x93933dae, 0x26264c6a, 0x36366c5a, 0x3f3f7e41, 0xf7f7f502, 0xcccc834f,
  0x3434685c, 0xa5a551f4, 0xe5e5d134, 0xf1f1f908, 0x7171e293, 0xd8d8ab73, 0x31316253, 0x15152a3f,
  0x0404080c, 0xc7c79552, 0x23234665, 0xc3c39d5e, 0x18183028, 0x969637a1, 0x05050a0f, 0x9a9a2fb5,
  0x07070e09, 0x12122436, 0x80801b9b, 0xe2e2df3d, 0xebebcd26, 0x27274e69, 0xb2b27fcd, 0x7575ea9f,
  0x0909121b, 0x83831d9e, 0x2c2c5874, 0x1a1a342e, 0x1b1b362d, 0x6e6edcb2, 0x5a5ab4ee, 0xa0a05bfb,
  0x5252a4f6, 0x3b3b764d, 0xd6d6b761, 0xb3b37dce, 0x2929527b, 0xe3e3dd3e, 0x2f2f5e71, 0x84841397,
  0x5353a6f5, 0xd1d1b968, 0x00000000, 0xededc12c, 0x20204060, 0xfcfce31f, 0xb1b179c8, 0x5b5bb6ed,
  0x6a6ad4be, 0xcbcb8d46, 0xbebe67d9, 0x3939724b, 0x4a4a94de, 0x4c4c98d4, 0x5858b0e8, 0xcfcf854a,
  0xd0d0bb6b, 0xefefc52a, 0xaaaa4fe5, 0xfbfbed16, 0x434386c5, 0x4d4d9ad7, 0x33336655, 0x85851194,
  0x45458acf, 0xf9f9e910, 0x02020406, 0x7f7ffe81, 0x5050a0f0, 0x3c3c7844, 0x9f9f25ba, 0xa8a84be3,
  0x5151a2f3, 0xa3a35dfe, 0x404080c0, 0x8f8f058a, 0x92923fad, 0x9d9d21bc, 0x38387048, 0xf5f5f104,
  0xbcbc63df, 0xb6b677c1, 0xdadaaf75, 0x21214263, 0x10102030, 0xffffe51a, 0xf3f3fd0e, 0xd2d2bf6d,
  0xcdcd814c, 0x0c0c1814, 0x13132635, 0xececc32f, 0x5f5fbee1, 0x979735a2, 0x444488cc, 0x17172e39,
  0xc4c49357, 0xa7a755f2, 0x7e7efc82, 0x3d3d7a47, 0x6464c8ac, 0x5d5dbae7, 0x1919322b, 0x7373e695,
  0x6060c0a0, 0x81811998, 0x4f4f9ed1, 0xdcdca37f, 0x22224466, 0x2a2a547e, 0x90903bab, 0x88880b83,
  0x46468cca, 0xeeeec729, 0xb8b86bd3, 0x1414283c, 0xdedea779, 0x5e5ebce2, 0x0b0b161d, 0xdbdbad76,
  0xe0e0db3b, 0x32326456, 0x3a3a744e, 0x0a0a141e, 0x494992db, 0x06060c0a, 0x2424486c, 0x5c5cb8e4,
  0xc2c29f5d, 0xd3d3bd6e, 0xacac43ef, 0x6262c4a6, 0x919139a8, 0x959531a4, 0xe4e4d337, 0x7979f28b,
  0xe7e7d532, 0xc8c88b43, 0x37376e59, 0x6d6ddab7, 0x8d8d018c, 0xd5d5b164, 0x4e4e9cd2, 0xa9a949e0,
  0x6c6cd8b4, 0x5656acfa, 0xf4f4f307, 0xeaeacf25, 0x6565caaf, 0x7a7af48e, 0xaeae47e9, 0x08081018,
  0xbaba6fd5, 0x7878f088, 0x25254a6f, 0x2e2e5c72, 0x1c1c3824, 0xa6a657f1, 0xb4b473c7, 0xc6c69751,
  0xe8e8cb23, 0xdddda17c, 0x7474e89c, 0x1f1f3e21, 0x4b4b96dd, 0xbdbd61dc, 0x8b8b0d86, 0x8a8a0f85,
  0x7070e090, 0x3e3e7c42, 0xb5b571c4, 0x6666ccaa, 0x484890d8, 0x03030605, 0xf6f6f701, 0x0e0e1c12,
  0x6161c2a3, 0x35356a5f, 0x5757aef9, 0xb9b969d0, 0x86861791, 0xc1c19958, 0x1d1d3a27, 0x9e9e27b9,
  0xe1e1d938, 0xf8f8eb13, 0x98982bb3, 0x11112233, 0x6969d2bb, 0xd9d9a970, 0x8e8e0789, 0x949433a7,
  0x9b9b2db6, 0x1e1e3c22, 0x87871592, 0xe9e9c920, 0xcece8749, 0x5555aaff, 0x28285078, 0xdfdfa57a,
  0x8c8c038f, 0xa1a159f8, 0x89890980, 0x0d0d1a17, 0xbfbf65da, 0xe6e6d731, 0x424284c6, 0x6868d0b8,
  0x414182c3, 0x999929b0, 0x2d2d5a77, 0x0f0f1e11, 0xb0b07bcb, 0x5454a8fc, 0xbbbb6dd6, 0x16162c3a
};

static const uint32_t te2[256] = {
  0x63c6a563, 0x7cf8847c, 0x77ee9977, 0x7bf68d7b, 0xf2ff0df2, 0x6bd6bd6b, 0x6fdeb16f, 0xc59154c5,
  0x30605030, 0x01020301, 0x67cea967, 0x2b567d2b, 0xfee719fe, 0xd7b562d7, 0xab4de6ab, 0x76ec9a76,
  0xca8f45ca, 0x821f9d82, 0xc98940c9, 0x7dfa877d, 0xfaef15fa, 0x59b2eb59, 0x478ec947, 0xf0fb0bf0,
  0xad41ecad, 0xd4b367d4, 0xa25ffda2, 0xaf45eaaf, 0x9c23bf9c, 0xa453f7a4, 0x72e49672, 0xc09b5bc0,
  0xb775c2b7, 0xfde11cfd, 0x933dae93, 0x264c6a26, 0x366c5a36, 0x3f7e413f, 0xf7f502f7, 0xcc834fcc,
  0x34685c34, 0xa551f4a5, 0xe5d134e5, 0xf1f908f1, 0x71e29371, 0xd8ab73d8, 0x31625331, 0x152a3f15,
  0x04080c04, 0xc79552c7, 0x23466523, 0xc39d5ec3, 0x18302818, 0x9637a196, 0x050a0f05, 0x9a2fb59a,
  0x070e0907, 0x12243612, 0x801b9b80, 0xe2df3de2, 0xebcd26eb, 0x274e6927, 0xb27fcdb2, 0x75ea9f75,
  0x09121b09, 0x831d9e83, 0x2c58742c, 0x1a342e1a, 0x1b362d1b, 0x6edcb26e, 0x5ab4ee5a, 0xa05bfba0,
  0x52a4f652, 0x3b764d3b, 0xd6b761d6, 0xb37dceb3, 0x29527b29, 0xe3dd3ee3, 0x2f5e712f, 0x84139784,
  0x53a6f553, 0xd1b968d1, 0x00000000, 0xedc12ced, 0x20406020, 0xfce31ffc, 0xb179c8b1, 0x5bb6ed5b,
  0x6ad4be6a, 0xcb8d46cb, 0xbe67d9be, 0x39724b39, 0x4a94de4a, 0x4c98d44c, 0x58b0e858, 0xcf854acf,
  0xd0bb6bd0, 0xefc52aef, 0xaa4fe5aa, 0xfbed16fb, 0x4386c543, 0x4d9ad74d, 0x33665533, 0x85119485,
  0x458acf45, 0xf9e910f9, 0x02040602, 0x7ffe817f, 0x50a0f050, 0x3c78443c, 0x9f25ba9f, 0xa84be3a8,
  0x51a2f351, 0xa35dfea3, 0x4080c040, 0x8f058a8f, 0x923fad92, 0x9d21bc9d, 0x38704838, 0xf5f104f5,
  0xbc63dfbc, 0xb677c1b6, 0xdaaf75da, 0x21426321, 0x10203010, 0xffe51aff, 0xf3fd0ef3, 0xd2bf6dd2,
  0xcd814ccd, 0x0c18140c, 0x13263513, 0xecc32fec, 0x5fbee15f, 0x9735a297, 0x4488cc44, 0x172e3917,
  0xc49357c4, 0xa755f2a7, 0x7efc827e, 0x3d7a473d, 0x64c8ac64, 0x5dbae75d, 0x19322b19, 0x73e69573,
  0x60c0a060, 0x81199881, 0x4f9ed14f, 0xdca37fdc, 0x22446622, 0x2a547e2a, 0x903bab90, 0x880b8388,
  0x468cca46, 0xeec729ee, 0xb86bd3b8, 0x14283c14, 0xdea779de, 0x5ebce25e, 0x0b161d0b, 0xdbad76db,
  0xe0db3be0, 0x32645632, 0x3a744e3a, 0x0a141e0a, 0x4992db49, 0x060c0a06, 0x24486c24, 0x5cb8e45c,
  0xc29f5dc2, 0xd3bd6ed3, 0xac43efac, 0x62c4a662, 0x9139a891, 0x9531a495, 0xe4d337e4, 0x79f28b79,
  0xe7d532e7, 0xc88b43c8, 0x376e5937, 0x6ddab76d, 0x8d018c8d, 0xd5b164d5, 0x4e9cd24e, 0xa949e0a9,
  0x6cd8b46c, 0x56acfa56, 0xf4f307f4, 0xeacf25ea, 0x65caaf65, 0x7af48e7a, 0xae47e9ae, 0x08101808,
  0xba6fd5ba, 0x78f08878, 0x254a6f25, 0x2e5c722e, 0x1c38241c, 0xa657f1a6, 0xb473c7b4, 0xc69751c6,
  0xe8cb23e8, 0xdda17cdd, 0x74e89c74, 0x1f3e211f, 0x4b96dd4b, 0xbd61dcbd, 0x8b0d868b, 0x8a0f858a,
  0x70e09070, 0x3e7c423e, 0xb571c4b5, 0x66ccaa66, 0x4890d848, 0x03060503, 0xf6f701f6, 0x0e1c120e,
  0x61c2a361, 0x356a5f35, 0x57aef957, 0xb969d0b9, 0x86179186, 0xc19958c1, 0x1d3a271d, 0x9e27b99e,
  0xe1d938e1, 0xf8eb13f8, 0x982bb398, 0x11223311, 0x69d2bb69, 0xd9a970d9, 0x8e07898e, 0x9433a794,
  0x9b2db69b, 0x1e3c221e, 0x87159287, 0xe9c920e9, 0xce8749ce, 0x55aaff55, 0x28507828, 0xdfa57adf,
  0x8c038f8c, 0xa159f8a1, 0x89098089, 0x0d1a170d, 0xbf65dabf, 0xe6d731e6, 0x4284c642, 0x68d0b868,
  0x4182c341, 0x9929b099, 0x2d5a772d, 0x0f1e110f, 0xb07bcbb0, 0x54a8fc54, 0xbb6dd6bb, 0x162c3a16,
};

static const uint32_t te3[256] = {
  0xc6a56363, 0xf8847c7c, 0xee997777, 0xf68d7b7b, 0xff0df2f2, 0xd6bd6b6b, 0xdeb16f6f, 0x9154c5c5,
  0x60503030, 0x02030101, 0xcea96767, 0x567d2b2b, 0xe719fefe, 0xb562d7d7, 0x4de6abab, 0xec9a7676,
  0x8f45caca, 0x1f9d8282, 0x8940c9c9, 0xfa877d7d, 0xef15fafa, 0xb2eb5959, 0x8ec94747, 0xfb0bf0f0,
  0x41ecadad, 0xb367d4d4, 0x5ffda2a2, 0x45eaafaf, 0x23bf9c9c, 0x53f7a4a4, 0xe4967272, 0x9b5bc0c0,
  0x75c2b7b7, 0xe11cfdfd, 0x3dae9393, 0x4c6a2626, 0x6c5a3636, 0x7e413f3f, 0xf502f7f7, 0x834fcccc,
  0x685c3434, 0x51f4a5a5, 0xd134e5e5, 0xf908f1f1, 0xe2937171, 0xab73d8d8, 0x62533131, 0x2a3f1515,
  0x080c0404, 0x9552c7c7, 0x46652323, 0x9d5ec3c3, 0x30281818, 0x37a19696, 0x0a0f0505, 0x2fb59a9a,
  0x0e090707, 0x24361212, 0x1b9b8080, 0xdf3de2e2, 0xcd26ebeb, 0x4e692727, 0x7fcdb2b2, 0xea9f7575,
  0x121b0909, 0x1d9e8383, 0x58742c2c, 0x342e1a1a, 0x362d1b1b, 0xdcb26e6e, 0xb4ee5a5a, 0x5bfba0a0,
  0xa4f65252, 0x764d3b3b, 0xb761d6d6, 0x7dceb3b3, 0x527b2929, 0xdd3ee3e3, 0x5e712f2f, 0x13978484,
  0xa6f55353, 0xb968d1d1, 0x00000000, 0xc12ceded, 0x40602020, 0xe31ffcfc, 0x79c8b1b1, 0xb6ed5b5b,
  0xd4be6a6a, 0x8d46cbcb, 0x67d9bebe, 0x724b3939, 0x94de4a4a, 0x98d44c4c, 0xb0e85858, 0x854acfcf,
  0xbb6bd0d0, 0xc52aefef, 0x4fe5aaaa, 0xed16fbfb, 0x86c54343, 0x9ad74d4d, 0x66553333, 0x11948585,
  0x8acf4545, 0xe910f9f9, 0x04060202, 0xfe817f7f, 0xa0f05050, 0x78443c3c, 0x25ba9f9f, 0x4be3a8a8,
  0xa2f35151, 0x5dfea3a3, 0x80c04040, 0x058a8f8f, 0x3fad9292, 0x21bc9d9d, 0x70483838, 0xf104f5f5,
  0x63dfbcbc, 0x77c1b6b6, 0xaf75dada, 0x42632121, 0x20301010, 0xe51affff, 0xfd0ef3f3, 0xbf6dd2d2,
  0x814ccdcd, 0x18140c0c, 0x26351313, 0xc32fecec, 0xbee15f5f, 0x35a29797, 0x88cc4444, 0x2e391717,
  0x9357c4c4, 0x55f2a7a7, 0xfc827e7e, 0x7a473d3d, 0xc8ac6464, 0xbae75d5d, 0x322b1919, 0xe6957373,
  0xc0a06060, 0x19988181, 0x9ed14f4f, 0xa37fdcdc, 0x44662222, 0x547e2a2a, 0x3bab9090, 0x0b838888,
  0x8cca4646, 0xc729eeee, 0x6bd3b8b8, 0x283c1414, 0xa779dede, 0xbce25e5e, 0x161d0b0b, 0xad76dbdb,
  0xdb3be0e0, 0x64563232, 0x744e3a3a, 0x141e0a0a, 0x92db4949, 0x0c0a0606, 0x486c2424, 0xb8e45c5c,
  0x9f5dc2c2, 0xbd6ed3d3, 0x43efacac, 0xc4a66262, 0x39a89191, 0x31a49595, 0xd337e4e4, 0xf28b7979,
  0xd532e7e7, 0x8b43c8c8, 0x6e593737, 0xdab76d6d, 0x018c8d8d, 0xb164d5d5, 0x9cd24e4e, 0x49e0a9a9,
  0xd8b46c6c, 0xacfa5656, 0xf307f4f4, 0xcf25eaea, 0xcaaf6565, 0xf48e7a7a, 0x47e9aeae, 0x10180808,
  0x6fd5baba, 0xf0887878, 0x4a6f2525, 0x5c722e2e, 0x38241c1c, 0x57f1a6a6, 0x73c7b4b4, 0x9751c6c6,
  0xcb23e8e8, 0xa17cdddd, 0xe89c7474, 0x3e211f1f, 0x96dd4b4b, 0x61dcbdbd, 0x0d868b8b, 0x0f858a8a,
  0xe0907070, 0x7c423e3e, 0x71c4b5b5, 0xccaa6666, 0x90d84848, 0x06050303, 0xf701f6f6, 0x1c120e0e,
  0xc2a36161, 0x6a5f3535, 0xaef95757, 0x69d0b9b9, 0x17918686, 0x9958c1c1, 0x3a271d1d, 0x27b99e9e,
  0xd938e1e1, 0xeb13f8f8, 0x2bb39898, 0x22331111, 0xd2bb6969, 0xa970d9d9, 0x07898e8e, 0x33a79494,
  0x2db69b9b, 0x3c221e1e, 0x15928787, 0xc920e9e9, 0x8749cece, 0xaaff5555, 0x50782828, 0xa57adfdf,
  0x038f8c8c, 0x59f8a1a1, 0x09808989, 0x1a170d0d, 0x65dabfbf, 0xd731e6e6, 0x84c64242, 0xd0b86868,
  0x82c34141, 0x29b09999, 0x5a772d2d, 0x1e110f0f, 0x7bcbb0b0, 0xa8fc5454, 0x6dd6bbbb, 0x2c3a1616,
};

static const uint32_t td0[] = {
  0x00000000, 0x0b0d090e, 0x161a121c, 0x1d171b12, 0x2c342438, 0x27392d36, 0x3a2e3624, 0x31233f2a,
  0x58684870, 0x5365417e, 0x4e725a6c, 0x457f5362, 0x745c6c48, 0x7f516546, 0x62467e54, 0x694b775a,
  0xb0d090e0, 0xbbdd99ee, 0xa6ca82fc, 0xadc78bf2, 0x9ce4b4d8, 0x97e9bdd6, 0x8afea6c4, 0x81f3afca,
  0xe8b8d890, 0xe3b5d19e, 0xfea2ca8c, 0xf5afc382, 0xc48cfca8, 0xcf81f5a6, 0xd296eeb4, 0xd99be7ba,
  0x7bbb3bdb, 0x70b632d5, 0x6da129c7, 0x66ac20c9, 0x578f1fe3, 0x5c8216ed, 0x41950dff, 0x4a9804f1,
  0x23d373ab, 0x28de7aa5, 0x35c961b7, 0x3ec468b9, 0x0fe75793, 0x04ea5e9d, 0x19fd458f, 0x12f04c81,
  0xcb6bab3b, 0xc066a235, 0xdd71b927, 0xd67cb029, 0xe75f8f03, 0xec52860d, 0xf1459d1f, 0xfa489411,
  0x9303e34b, 0x980eea45, 0x8519f157, 0x8e14f859, 0xbf37c773, 0xb43ace7d, 0xa92dd56f, 0xa220dc61,
  0xf66d76ad, 0xfd607fa3, 0xe07764b1, 0xeb7a6dbf, 0xda595295, 0xd1545b9b, 0xcc434089, 0xc74e4987,
  0xae053edd, 0xa50837d3, 0xb81f2cc1, 0xb31225cf, 0x82311ae5, 0x893c13eb, 0x942b08f9, 0x9f2601f7,
  0x46bde64d, 0x4db0ef43, 0x50a7f451, 0x5baafd5f, 0x6a89c275, 0x6184cb7b, 0x7c93d069, 0x779ed967,
  0x1ed5ae3d, 0x15d8a733, 0x08cfbc21, 0x03c2b52f, 0x32e18a05, 0x39ec830b, 0x24fb9819, 0x2ff69117,
  0x8dd64d76, 0x86db4478, 0x9bcc5f6a, 0x90c15664, 0xa1e2694e, 0xaaef6040, 0xb7f87b52, 0xbcf5725c,
  0xd5be0506, 0xdeb30c08, 0xc3a4171a, 0xc8a91e14, 0xf98a213e, 0xf2872830, 0xef903322, 0xe49d3a2c,
  0x3d06dd96, 0x360bd498, 0x2b1ccf8a, 0x2011c684, 0x1132f9ae, 0x1a3ff0a0, 0x0728ebb2, 0x0c25e2bc,
  0x656e95e6, 0x6e639ce8, 0x737487fa, 0x78798ef4, 0x495ab1de, 0x4257b8d0, 0x5f40a3c2, 0x544daacc,
  0xf7daec41, 0xfcd7e54f, 0xe1c0fe5d, 0xeacdf753, 0xdbeec879, 0xd0e3c177, 0xcdf4da65, 0xc6f9d36b,
  0xafb2a431, 0xa4bfad3f, 0xb9a8b62d, 0xb2a5bf23, 0x83868009, 0x888b8907, 0x959c9215, 0x9e919b1b,
  0x470a7ca1, 0x4c0775af, 0x51106ebd, 0x5a1d67b3, 0x6b3e5899, 0x60335197, 0x7d244a85, 0x7629438b,
  0x1f6234d1, 0x146f3ddf, 0x097826cd, 0x02752fc3, 0x335610e9, 0x385b19e7, 0x254c02f5, 0x2e410bfb,
  0x8c61d79a, 0x876cde94, 0x9a7bc586, 0x9176cc88, 0xa055f3a2, 0xab58faac, 0xb64fe1be, 0xbd42e8b0,
  0xd4099fea, 0xdf0496e4, 0xc2138df6, 0xc91e84f8, 0xf83dbbd2, 0xf330b2dc, 0xee27a9ce, 0xe52aa0c0,
  0x3cb1477a, 0x37bc4e74, 0x2aab5566, 0x21a65c68, 0x10856342, 0x1b886a4c, 0x069f715e, 0x0d927850,
  0x64d90f0a, 0x6fd40604, 0x72c31d16, 0x79ce1418, 0x48ed2b32, 0x43e0223c, 0x5ef7392e, 0x55fa3020,
  0x01b79aec, 0x0aba93e2, 0x17ad88f0, 0x1ca081fe, 0x2d83bed4, 0x268eb7da, 0x3b99acc8, 0x3094a5c6,
  0x59dfd29c, 0x52d2db92, 0x4fc5c080, 0x44c8c98e, 0x75ebf6a4, 0x7ee6ffaa, 0x63f1e4b8, 0x68fcedb6,
  0xb1670a0c, 0xba6a0302, 0xa77d1810, 0xac70111e, 0x9d532e34, 0x965e273a, 0x8b493c28, 0x80443526,
  0xe90f427c, 0xe2024b72, 0xff155060, 0xf418596e, 0xc53b6644, 0xce366f4a, 0xd3217458, 0xd82c7d56,
  0x7a0ca137, 0x7101a839, 0x6c16b32b, 0x671bba25, 0x5638850f, 0x5d358c01, 0x40229713, 0x4b2f9e1d,
  0x2264e947, 0x2969e049, 0x347efb5b, 0x3f73f255, 0x0e50cd7f, 0x055dc471, 0x184adf63, 0x1347d66d,
  0xcadc31d7, 0xc1d138d9, 0xdcc623cb, 0xd7cb2ac5, 0xe6e815ef, 0xede51ce1, 0xf0f207f3, 0xfbff0efd,
  0x92b479a7, 0x99b970a9, 0x84ae6bbb, 0x8fa362b5, 0xbe805d9f, 0xb58d5491, 0xa89a4f83, 0xa397468d,
};

static const uint32_t td1[] = {
  0x00000000, 0x0d090e0b, 0x1a121c16, 0x171b121d, 0x3424382c, 0x392d3627, 0x2e36243a, 0x233f2a31,
  0x68487058, 0x65417e53, 0x725a6c4e, 0x7f536245, 0x5c6c4874, 0x5165467f, 0x467e5462, 0x4b775a69,
  0xd090e0b0, 0xdd99eebb, 0xca82fca6, 0xc78bf2ad, 0xe4b4d89c, 0xe9bdd697, 0xfea6c48a, 0xf3afca81,
  0xb8d890e8, 0xb5d19ee3, 0xa2ca8cfe, 0xafc382f5, 0x8cfca8c4, 0x81f5a6cf, 0x96eeb4d2, 0x9be7bad9,
  0xbb3bdb7b, 0xb632d570, 0xa129c76d, 0xac20c966, 0x8f1fe357, 0x8216ed5c, 0x950dff41, 0x9804f14a,
  0xd373ab23, 0xde7aa528, 0xc961b735, 0xc468b93e, 0xe757930f, 0xea5e9d04, 0xfd458f19, 0xf04c8112,
  0x6bab3bcb, 0x66a235c0, 0x71b927dd, 0x7cb029d6, 0x5f8f03e7, 0x52860dec, 0x459d1ff1, 0x489411fa,
  0x03e34b93, 0x0eea4598, 0x19f15785, 0x14f8598e, 0x37c773bf, 0x3ace7db4, 0x2dd56fa9, 0x20dc61a2,
  0x6d76adf6, 0x607fa3fd, 0x7764b1e0, 0x7a6dbfeb, 0x595295da, 0x545b9bd1, 0x434089cc, 0x4e4987c7,
  0x053eddae, 0x0837d3a5, 0x1f2cc1b8, 0x1225cfb3, 0x311ae582, 0x3c13eb89, 0x2b08f994, 0x2601f79f,
  0xbde64d46, 0xb0ef434d, 0xa7f45150, 0xaafd5f5b, 0x89c2756a, 0x84cb7b61, 0x93d0697c, 0x9ed96777,
  0xd5ae3d1e, 0xd8a73315, 0xcfbc2108, 0xc2b52f03, 0xe18a0532, 0xec830b39, 0xfb981924, 0xf691172f,
  0xd64d768d, 0xdb447886, 0xcc5f6a9b, 0xc1566490, 0xe2694ea1, 0xef6040aa, 0xf87b52b7, 0xf5725cbc,
  0xbe0506d5, 0xb30c08de, 0xa4171ac3, 0xa91e14c8, 0x8a213ef9, 0x872830f2, 0x903322ef, 0x9d3a2ce4,
  0x06dd963d, 0x0bd49836, 0x1ccf8a2b, 0x11c68420, 0x32f9ae11, 0x3ff0a01a, 0x28ebb207, 0x25e2bc0c,
  0x6e95e665, 0x639ce86e, 0x7487fa73, 0x798ef478, 0x5ab1de49, 0x57b8d042, 0x40a3c25f, 0x4daacc54,
  0xdaec41f7, 0xd7e54ffc, 0xc0fe5de1, 0xcdf753ea, 0xeec879db, 0xe3c177d0, 0xf4da65cd, 0xf9d36bc6,
  0xb2a431af, 0xbfad3fa4, 0xa8b62db9, 0xa5bf23b2, 0x86800983, 0x8b890788, 0x9c921595, 0x919b1b9e,
  0x0a7ca147, 0x0775af4c, 0x106ebd51, 0x1d67b35a, 0x3e58996b, 0x33519760, 0x244a857d, 0x29438b76,
  0x6234d11f, 0x6f3ddf14, 0x7826cd09, 0x752fc302, 0x5610e933, 0x5b19e738, 0x4c02f525, 0x410bfb2e,
  0x61d79a8c, 0x6cde9487, 0x7bc5869a, 0x76cc8891, 0x55f3a2a0, 0x58faacab, 0x4fe1beb6, 0x42e8b0bd,
  0x099fead4, 0x0496e4df, 0x138df6c2, 0x1e84f8c9, 0x3dbbd2f8, 0x30b2dcf3, 0x27a9ceee, 0x2aa0c0e5,
  0xb1477a3c, 0xbc4e7437, 0xab55662a, 0xa65c6821, 0x85634210, 0x886a4c1b, 0x9f715e06, 0x9278500d,
  0xd90f0a64, 0xd406046f, 0xc31d1672, 0xce141879, 0xed2b3248, 0xe0223c43, 0xf7392e5e, 0xfa302055,
  0xb79aec01, 0xba93e20a, 0xad88f017, 0xa081fe1c, 0x83bed42d, 0x8eb7da26, 0x99acc83b, 0x94a5c630,
  0xdfd29c59, 0xd2db9252, 0xc5c0804f, 0xc8c98e44, 0xebf6a475, 0xe6ffaa7e, 0xf1e4b863, 0xfcedb668,
  0x670a0cb1, 0x6a0302ba, 0x7d1810a7, 0x70111eac, 0x532e349d, 0x5e273a96, 0x493c288b, 0x44352680,
  0x0f427ce9, 0x024b72e2, 0x155060ff, 0x18596ef4, 0x3b6644c5, 0x366f4ace, 0x217458d3, 0x2c7d56d8,
  0x0ca1377a, 0x01a83971, 0x16b32b6c, 0x1bba2567, 0x38850f56, 0x358c015d, 0x22971340, 0x2f9e1d4b,
  0x64e94722, 0x69e04929, 0x7efb5b34, 0x73f2553f, 0x50cd7f0e, 0x5dc47105, 0x4adf6318, 0x47d66d13,
  0xdc31d7ca, 0xd138d9c1, 0xc623cbdc, 0xcb2ac5d7, 0xe815efe6, 0xe51ce1ed, 0xf207f3f0, 0xff0efdfb,
  0xb479a792, 0xb970a999, 0xae6bbb84, 0xa362b58f, 0x805d9fbe, 0x8d5491b5, 0x9a4f83a8, 0x97468da3,
};

static const uint32_t td2[] = {
  0x00000000, 0x090e0b0d, 0x121c161a, 0x1b121d17, 0x24382c34, 0x2d362739, 0x36243a2e, 0x3f2a3123,
  0x48705868, 0x417e5365, 0x5a6c4e72, 0x5362457f, 0x6c48745c, 0x65467f51, 0x7e546246, 0x775a694b,
  0x90e0b0d0, 0x99eebbdd, 0x82fca6ca, 0x8bf2adc7, 0xb4d89ce4, 0xbdd697e9, 0xa6c48afe, 0xafca81f3,
  0xd890e8b8, 0xd19ee3b5, 0xca8cfea2, 0xc382f5af, 0xfca8c48c, 0xf5a6cf81, 0xeeb4d296, 0xe7bad99b,
  0x3bdb7bbb, 0x32d570b6, 0x29c76da1, 0x20c966ac, 0x1fe3578f, 0x16ed5c82, 0x0dff4195, 0x04f14a98,
  0x73ab23d3, 0x7aa528de, 0x61b735c9, 0x68b93ec4, 0x57930fe7, 0x5e9d04ea, 0x458f19fd, 0x4c8112f0,
  0xab3bcb6b, 0xa235c066, 0xb927dd71, 0xb029d67c, 0x8f03e75f, 0x860dec52, 0x9d1ff145, 0x9411fa48,
  0xe34b9303, 0xea45980e, 0xf1578519, 0xf8598e14, 0xc773bf37, 0xce7db43a, 0xd56fa92d, 0xdc61a220,
  0x76adf66d, 0x7fa3fd60, 0x64b1e077, 0x6dbfeb7a, 0x5295da59, 0x5b9bd154, 0x4089cc43, 0x4987c74e,
  0x3eddae05, 0x37d3a508, 0x2cc1b81f, 0x25cfb312, 0x1ae58231, 0x13eb893c, 0x08f9942b, 0x01f79f26,
  0xe64d46bd, 0xef434db0, 0xf45150a7, 0xfd5f5baa, 0xc2756a89, 0xcb7b6184, 0xd0697c93, 0xd967779e,
  0xae3d1ed5, 0xa73315d8, 0xbc2108cf, 0xb52f03c2, 0x8a0532e1, 0x830b39ec, 0x981924fb, 0x91172ff6,
  0x4d768dd6, 0x447886db, 0x5f6a9bcc, 0x566490c1, 0x694ea1e2, 0x6040aaef, 0x7b52b7f8, 0x725cbcf5,
  0x0506d5be, 0x0c08deb3, 0x171ac3a4, 0x1e14c8a9, 0x213ef98a, 0x2830f287, 0x3322ef90, 0x3a2ce49d,
  0xdd963d06, 0xd498360b, 0xcf8a2b1c, 0xc6842011, 0xf9ae1132, 0xf0a01a3f, 0xebb20728, 0xe2bc0c25,
  0x95e6656e, 0x9ce86e63, 0x87fa7374, 0x8ef47879, 0xb1de495a, 0xb8d04257, 0xa3c25f40, 0xaacc544d,
  0xec41f7da, 0xe54ffcd7, 0xfe5de1c0, 0xf753eacd, 0xc879dbee, 0xc177d0e3, 0xda65cdf4, 0xd36bc6f9,
  0xa431afb2, 0xad3fa4bf, 0xb62db9a8, 0xbf23b2a5, 0x80098386, 0x8907888b, 0x9215959c, 0x9b1b9e91,
  0x7ca1470a, 0x75af4c07, 0x6ebd5110, 0x67b35a1d, 0x58996b3e, 0x51976033, 0x4a857d24, 0x438b7629,
  0x34d11f62, 0x3ddf146f, 0x26cd0978, 0x2fc30275, 0x10e93356, 0x19e7385b, 0x02f5254c, 0x0bfb2e41,
  0xd79a8c61, 0xde94876c, 0xc5869a7b, 0xcc889176, 0xf3a2a055, 0xfaacab58, 0xe1beb64f, 0xe8b0bd42,
  0x9fead409, 0x96e4df04, 0x8df6c213, 0x84f8c91e, 0xbbd2f83d, 0xb2dcf330, 0xa9ceee27, 0xa0c0e52a,
  0x477a3cb1, 0x4e7437bc, 0x55662aab, 0x5c6821a6, 0x63421085, 0x6a4c1b88, 0x715e069f, 0x78500d92,
  0x0f0a64d9, 0x06046fd4, 0x1d1672c3, 0x141879ce, 0x2b3248ed, 0x223c43e0, 0x392e5ef7, 0x302055fa,
  0x9aec01b7, 0x93e20aba, 0x88f017ad, 0x81fe1ca0, 0xbed42d83, 0xb7da268e, 0xacc83b99, 0xa5c63094,
  0xd29c59df, 0xdb9252d2, 0xc0804fc5, 0xc98e44c8, 0xf6a475eb, 0xffaa7ee6, 0xe4b863f1, 0xedb668fc,
  0x0a0cb167, 0x0302ba6a, 0x1810a77d, 0x111eac70, 0x2e349d53, 0x273a965e, 0x3c288b49, 0x35268044,
  0x427ce90f, 0x4b72e202, 0x5060ff15, 0x596ef418, 0x6644c53b, 0x6f4ace36, 0x7458d321, 0x7d56d82c,
  0xa1377a0c, 0xa8397101, 0xb32b6c16, 0xba25671b, 0x850f5638, 0x8c015d35, 0x97134022, 0x9e1d4b2f,
  0xe9472264, 0xe0492969, 0xfb5b347e, 0xf2553f73, 0xcd7f0e50, 0xc471055d, 0xdf63184a, 0xd66d1347,
  0x31d7cadc, 0x38d9c1d1, 0x23cbdcc6, 0x2ac5d7cb, 0x15efe6e8, 0x1ce1ede5, 0x07f3f0f2, 0x0efdfbff,
  0x79a792b4, 0x70a999b9, 0x6bbb84ae, 0x62b58fa3, 0x5d9fbe80, 0x5491b58d, 0x4f83a89a, 0x468da397,

};

static const uint32_t td3[] = {
  0x00000000, 0x0e0b0d09, 0x1c161a12, 0x121d171b, 0x382c3424, 0x3627392d, 0x243a2e36, 0x2a31233f,
  0x70586848, 0x7e536541, 0x6c4e725a, 0x62457f53, 0x48745c6c, 0x467f5165, 0x5462467e, 0x5a694b77,
  0xe0b0d090, 0xeebbdd99, 0xfca6ca82, 0xf2adc78b, 0xd89ce4b4, 0xd697e9bd, 0xc48afea6, 0xca81f3af,
  0x90e8b8d8, 0x9ee3b5d1, 0x8cfea2ca, 0x82f5afc3, 0xa8c48cfc, 0xa6cf81f5, 0xb4d296ee, 0xbad99be7,
  0xdb7bbb3b, 0xd570b632, 0xc76da129, 0xc966ac20, 0xe3578f1f, 0xed5c8216, 0xff41950d, 0xf14a9804,
  0xab23d373, 0xa528de7a, 0xb735c961, 0xb93ec468, 0x930fe757, 0x9d04ea5e, 0x8f19fd45, 0x8112f04c,
  0x3bcb6bab, 0x35c066a2, 0x27dd71b9, 0x29d67cb0, 0x03e75f8f, 0x0dec5286, 0x1ff1459d, 0x11fa4894,
  0x4b9303e3, 0x45980eea, 0x578519f1, 0x598e14f8, 0x73bf37c7, 0x7db43ace, 0x6fa92dd5, 0x61a220dc,
  0xadf66d76, 0xa3fd607f, 0xb1e07764, 0xbfeb7a6d, 0x95da5952, 0x9bd1545b, 0x89cc4340, 0x87c74e49,
  0xddae053e, 0xd3a50837, 0xc1b81f2c, 0xcfb31225, 0xe582311a, 0xeb893c13, 0xf9942b08, 0xf79f2601,
  0x4d46bde6, 0x434db0ef, 0x5150a7f4, 0x5f5baafd, 0x756a89c2, 0x7b6184cb, 0x697c93d0, 0x67779ed9,
  0x3d1ed5ae, 0x3315d8a7, 0x2108cfbc, 0x2f03c2b5, 0x0532e18a, 0x0b39ec83, 0x1924fb98, 0x172ff691,
  0x768dd64d, 0x7886db44, 0x6a9bcc5f, 0x6490c156, 0x4ea1e269, 0x40aaef60, 0x52b7f87b, 0x5cbcf572,
  0x06d5be05, 0x08deb30c, 0x1ac3a417, 0x14c8a91e, 0x3ef98a21, 0x30f28728, 0x22ef9033, 0x2ce49d3a,
  0x963d06dd, 0x98360bd4, 0x8a2b1ccf, 0x842011c6, 0xae1132f9, 0xa01a3ff0, 0xb20728eb, 0xbc0c25e2,
  0xe6656e95, 0xe86e639c, 0xfa737487, 0xf478798e, 0xde495ab1, 0xd04257b8, 0xc25f40a3, 0xcc544daa,
  0x41f7daec, 0x4ffcd7e5, 0x5de1c0fe, 0x53eacdf7, 0x79dbeec8, 0x77d0e3c1, 0x65cdf4da, 0x6bc6f9d3,
  0x31afb2a4, 0x3fa4bfad, 0x2db9a8b6, 0x23b2a5bf, 0x09838680, 0x07888b89, 0x15959c92, 0x1b9e919b,
  0xa1470a7c, 0xaf4c0775, 0xbd51106e, 0xb35a1d67, 0x996b3e58, 0x97603351, 0x857d244a, 0x8b762943,
  0xd11f6234, 0xdf146f3d, 0xcd097826, 0xc302752f, 0xe9335610, 0xe7385b19, 0xf5254c02, 0xfb2e410b,
  0x9a8c61d7, 0x94876cde, 0x869a7bc5, 0x889176cc, 0xa2a055f3, 0xacab58fa, 0xbeb64fe1, 0xb0bd42e8,
  0xead4099f, 0xe4df0496, 0xf6c2138d, 0xf8c91e84, 0xd2f83dbb, 0xdcf330b2, 0xceee27a9, 0xc0e52aa0,
  0x7a3cb147, 0x7437bc4e, 0x662aab55, 0x6821a65c, 0x42108563, 0x4c1b886a, 0x5e069f71, 0x500d9278,
  0x0a64d90f, 0x046fd406, 0x1672c31d, 0x1879ce14, 0x3248ed2b, 0x3c43e022, 0x2e5ef739, 0x2055fa30,
  0xec01b79a, 0xe20aba93, 0xf017ad88, 0xfe1ca081, 0xd42d83be, 0xda268eb7, 0xc83b99ac, 0xc63094a5,
  0x9c59dfd2, 0x9252d2db, 0x804fc5c0, 0x8e44c8c9, 0xa475ebf6, 0xaa7ee6ff, 0xb863f1e4, 0xb668fced,
  0x0cb1670a, 0x02ba6a03, 0x10a77d18, 0x1eac7011, 0x349d532e, 0x3a965e27, 0x288b493c, 0x26804435,
  0x7ce90f42, 0x72e2024b, 0x60ff1550, 0x6ef41859, 0x44c53b66, 0x4ace366f, 0x58d32174, 0x56d82c7d,
  0x377a0ca1, 0x397101a8, 0x2b6c16b3, 0x25671bba, 0x0f563885, 0x015d358c, 0x13402297, 0x1d4b2f9e,
  0x472264e9, 0x492969e0, 0x5b347efb, 0x553f73f2, 0x7f0e50cd, 0x71055dc4, 0x63184adf, 0x6d1347d6,
  0xd7cadc31, 0xd9c1d138, 0xcbdcc623, 0xc5d7cb2a, 0xefe6e815, 0xe1ede51c, 0xf3f0f207, 0xfdfbff0e,
  0xa792b479, 0xa999b970, 0xbb84ae6b, 0xb58fa362, 0x9fbe805d, 0x91b58d54, 0x83a89a4f, 0x8da39746,

};

static const uint8_t rcons[] = {
  0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

/* TODO : implement proper phantom key loading unloading */
static const uint8_t DUMMY_KEY[THSM_BLOCK_SIZE] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                                                   0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
                                                  };

static const uint8_t null_nonce[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

//--------------------------------------------------------------------------------------------------
// Global Variables
//--------------------------------------------------------------------------------------------------

static ADC *adc = new ADC();
static FastCRC32 CRC32;

static THSM_PKT_REQ request;
static THSM_PKT_RESP response;
static aes_state_t phantom_key;
static THSM_BUFFER thsm_buffer;
static hmac_sha1_ctx_t hmac_sha1_ctx;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------
void setup() {
  pinMode(PIN_LED, OUTPUT);
  pinMode(PIN_ADC1, INPUT); //pin 23 single ended
  pinMode(PIN_ADC2, INPUT); //pin 23 single ended
  adc->setReference(ADC_REF_1V2, ADC_0);
  adc->setReference(ADC_REF_1V2, ADC_1);
  adc->setSamplingSpeed(ADC_HIGH_SPEED);
  Serial.begin(9600);
  reset();

  /* TODO : implement proper phantom key loading unloading */
  memcpy(phantom_key.bytes, DUMMY_KEY, sizeof(DUMMY_KEY));
  memset(&thsm_buffer, 0, sizeof(thsm_buffer));
}

void loop() {
  uint8_t idx = 0;
  uint8_t remaining = 0;
  uint8_t state = STATE_WAIT_BCNT;
  uint8_t zero_ctr = 0;

  while (1) {
    if (Serial.available()) {
      // read character from USB
      int b = Serial.read();

      /* detect reset */
      zero_ctr = (b == 0) ? (zero_ctr + 1) : 0;
      if (zero_ctr == THSM_MAX_PKT_SIZE)
      {
        reset();
        zero_ctr = 0;
        state = STATE_WAIT_BCNT;
        continue;
      }

      // dispatch state
      switch (state)
      {
        case STATE_WAIT_BCNT:
          request.bcnt = (b > (THSM_MAX_PKT_SIZE + 1)) ? (THSM_MAX_PKT_SIZE + 1) : b;
          remaining = b;
          state = STATE_WAIT_CMD;
          break;

        case STATE_WAIT_CMD:
          if (remaining-- > 0)
          {
            request.cmd = b;
            if (remaining == 0)
            {
              execute_cmd();
              zero_ctr = 0;
              state = STATE_WAIT_BCNT;
            }
            else
            {
              idx = 0;
              state = STATE_WAIT_PAYLOAD;
            }
          }
          else
          {
            zero_ctr = 0;
            state = STATE_WAIT_BCNT;
          }
          break;

        case STATE_WAIT_PAYLOAD:
          if (remaining-- > 0)
          {
            /* cap index by THSM_MAX_PKT_SIZE */
            if (idx < THSM_MAX_PKT_SIZE) {
              request.payload.raw[idx++] = b;
            }
          }

          if (remaining == 0)
          {
            execute_cmd();
            reset();
            zero_ctr = 0;
            state = STATE_WAIT_BCNT;
          }
          break;
      }
    }
  }
}

static void reset()
{
  memset(&request,  0, sizeof(request));
  memset(&response, 0, sizeof(response));
  memset(&hmac_sha1_ctx, 0, sizeof(hmac_sha1_ctx));
  memset(&thsm_buffer, 0, sizeof(thsm_buffer));
}

static void execute_cmd()
{
  /* switch on LED */
  digitalWrite(PIN_LED, HIGH);

  switch (request.cmd)
  {
    case THSM_CMD_AEAD_GENERATE:
      cmd_aead_generate();
      break;
    case THSM_CMD_BUFFER_AEAD_GENERATE:
      break;
    case THSM_CMD_RANDOM_AEAD_GENERATE:
      break;
    case THSM_CMD_AEAD_DECRYPT_CMP:
      break;
    case THSM_CMD_DB_YUBIKEY_AEAD_STORE:
      break;
    case THSM_CMD_AEAD_YUBIKEY_OTP_DECODE:
      break;
    case THSM_CMD_DB_OTP_VALIDATE:
      break;
    case THSM_CMD_DB_YUBIKEY_AEAD_STORE2:
      break;
    case THSM_CMD_AES_ECB_BLOCK_ENCRYPT:
      cmd_ecb_encrypt();
      break;
    case THSM_CMD_AES_ECB_BLOCK_DECRYPT:
      cmd_ecb_decrypt();
      break;
    case THSM_CMD_AES_ECB_BLOCK_DECRYPT_CMP:
      cmd_ecb_decrypt_cmp();
      break;
    case THSM_CMD_HMAC_SHA1_GENERATE:
      cmd_hmac_sha1_generate();
      break;
    case THSM_CMD_TEMP_KEY_LOAD:
      break;
    case THSM_CMD_BUFFER_LOAD:
      cmd_buffer_load();
      break;
    case THSM_CMD_BUFFER_RANDOM_LOAD:
      cmd_buffer_random_load();
      break;
    case THSM_CMD_NONCE_GET:
      cmd_nonce_get();
      break;
    case THSM_CMD_ECHO:
      cmd_echo();
      break;
    case THSM_CMD_RANDOM_GENERATE:
      cmd_random_generate();
      break;
    case THSM_CMD_RANDOM_RESEED:
      cmd_random_reseed();
      break;
    case THSM_CMD_SYSTEM_INFO_QUERY:
      cmd_info_query();
      break;
    case THSM_CMD_HSM_UNLOCK:
      cmd_hsm_unlock();
      break;
    case THSM_CMD_KEY_STORE_DECRYPT:
      cmd_key_store_decrypt();
      break;
    case THSM_CMD_MONITOR_EXIT:
      break;
  }

  /* switch off LED */
  digitalWrite(PIN_LED, LOW);
}

//--------------------------------------------------------------------------------------------------
// Command Handlers
//--------------------------------------------------------------------------------------------------
static void cmd_echo()
{
  /* cap echo data length to sizeof(THSM_ECHO_REQ::data) */
  uint8_t len = request.payload.echo.data_len;
  uint8_t max = sizeof(request.payload.echo.data);
  request.payload.echo.data_len = (len > max) ? max : len;
  request.bcnt = request.payload.echo.data_len + 2;

  memcpy(response.payload.echo.data, request.payload.echo.data, request.payload.echo.data_len);
  response.bcnt = request.bcnt;
  response.cmd = request.cmd | THSM_FLAG_RESPONSE;
  response.payload.echo.data_len = request.payload.echo.data_len;
  Serial.write((const char *)&response, (response.bcnt + 1));
}

static void cmd_info_query()
{
  response.bcnt = sizeof(response.payload.system_info) + 1;
  response.cmd = request.cmd | THSM_FLAG_RESPONSE;
  response.payload.system_info.version_major = 1;
  response.payload.system_info.version_minor = 0;
  response.payload.system_info.version_build = 4;
  response.payload.system_info.protocol_version = THSM_PROTOCOL_VERSION;
  memcpy(response.payload.system_info.system_uid, "Teensy HSM  ", SYSTEM_ID_SIZE);
  Serial.write((const char *)&response, response.bcnt + 1);
}

static void cmd_random_generate() {
  uint8_t len = request.payload.random_generate.bytes_len;
  uint8_t max = sizeof(response.payload.random_generate.bytes);
  request.payload.random_generate.bytes_len = (len > max) ? max : len;
  request.bcnt = request.payload.random_generate.bytes_len + 2;

  response.bcnt = request.bcnt;
  response.cmd = request.cmd | THSM_FLAG_RESPONSE;
  response.payload.random_generate.bytes_len = request.payload.random_generate.bytes_len;
  adc_rng_read(response.payload.random_generate.bytes, response.payload.random_generate.bytes_len);
  Serial.write((const char *)&response, response.bcnt + 1);
}

static void cmd_random_reseed() {
  response.bcnt = 2;
  response.cmd = request.cmd | THSM_FLAG_RESPONSE;
  response.payload.random_reseed.status = THSM_STATUS_OK;
  Serial.write((const char *)&response, response.bcnt + 1);
}

static void cmd_ecb_encrypt() {
  /* common response values */
  response.bcnt = sizeof(response.payload.ecb_encrypt) + 1;
  response.cmd = request.cmd | THSM_FLAG_RESPONSE;
  memcpy(response.payload.ecb_encrypt.key_handle, request.payload.ecb_encrypt.key_handle, sizeof(request.payload.ecb_encrypt.key_handle));
  memset(response.payload.ecb_encrypt.ciphertext, 0, sizeof(response.payload.ecb_encrypt.ciphertext));

  uint32_t key_handle = read_uint32(request.payload.ecb_encrypt.key_handle);
  if (request.bcnt != (sizeof(request.payload.ecb_encrypt) + 1)) {
    response.payload.ecb_encrypt.status = THSM_STATUS_INVALID_PARAMETER;
  } else if (key_handle != THSM_TEMP_KEY_HANDLE) {
    response.payload.ecb_encrypt.status = THSM_STATUS_KEY_HANDLE_INVALID;
  } else {
    aes_state_t pt;
    aes_state_t ct;
    aes_state_t ck;

    response.payload.ecb_encrypt.status = THSM_STATUS_OK;
    memcpy(&ck, &phantom_key, sizeof(phantom_key));
    memcpy(pt.bytes, request.payload.ecb_encrypt.plaintext, sizeof(request.payload.ecb_encrypt.plaintext));

    /* perform encryption */
    aes_ecb_encrypt(&ct, &pt, &ck);
    memcpy(response.payload.ecb_encrypt.ciphertext, ct.bytes, sizeof(ct.bytes));
  }

  /* send response */
  Serial.write((const char *)&response, response.bcnt + 1);
}

static void cmd_hmac_sha1_generate() {
  /* set common response */
  response.bcnt = sizeof(response.payload.hmac_sha1_generate) + 1;
  response.cmd = request.cmd | THSM_FLAG_RESPONSE;
  memcpy(response.payload.hmac_sha1_generate.key_handle, request.payload.hmac_sha1_generate.key_handle, sizeof(request.payload.hmac_sha1_generate.key_handle));
  memset(response.payload.hmac_sha1_generate.data, 0, sizeof(response.payload.hmac_sha1_generate.data));
  response.payload.hmac_sha1_generate.data_len = 0;
  response.payload.hmac_sha1_generate.status = THSM_STATUS_OK;

  /* check given key handle */
  uint32_t key_handle = read_uint32(request.payload.hmac_sha1_generate.key_handle);
  if (request.bcnt > (sizeof(request.payload.hmac_sha1_generate) + 1)) {
    response.payload.hmac_sha1_generate.status = THSM_STATUS_INVALID_PARAMETER;
  } else if (request.payload.hmac_sha1_generate.data_len > sizeof(request.payload.hmac_sha1_generate.data)) {
    response.payload.hmac_sha1_generate.status = THSM_STATUS_INVALID_PARAMETER;
  } else if (key_handle != THSM_TEMP_KEY_HANDLE) {
    response.payload.hmac_sha1_generate.status = THSM_STATUS_KEY_HANDLE_INVALID;
  } else {
    /* init hmac */
    if (request.payload.hmac_sha1_generate.flags & THSM_HMAC_RESET) {
      hmac_sha1_init(&hmac_sha1_ctx, phantom_key.bytes, sizeof(phantom_key.bytes));
    }

    /* update hmac */
    if (request.payload.hmac_sha1_generate.data_len > 0) {
      hmac_sha1_update(&hmac_sha1_ctx, request.payload.hmac_sha1_generate.data, request.payload.hmac_sha1_generate.data_len);
    }

    /* finalize hmac */
    if (request.payload.hmac_sha1_generate.flags & THSM_HMAC_FINAL) {
      if (request.payload.hmac_sha1_generate.flags & THSM_HMAC_SHA1_TO_BUFFER) {
        hmac_sha1_final(&hmac_sha1_ctx, thsm_buffer.data);
        thsm_buffer.data_len = THSM_SHA1_HASH_SIZE;
      } else {
        hmac_sha1_final(&hmac_sha1_ctx, response.payload.hmac_sha1_generate.data);
        response.payload.hmac_sha1_generate.data_len = THSM_SHA1_HASH_SIZE;
      }
    }
  }

  /* send response */
  Serial.write((const char *)&response, response.bcnt + 1);
}

static void cmd_ecb_decrypt() {
  /* common response values */
  response.bcnt = sizeof(response.payload.ecb_decrypt) + 1;
  response.cmd = request.cmd | THSM_FLAG_RESPONSE;
  memcpy(response.payload.ecb_decrypt.key_handle, request.payload.ecb_decrypt.key_handle, sizeof(request.payload.ecb_decrypt.key_handle));
  memset(response.payload.ecb_decrypt.plaintext, 0, sizeof(response.payload.ecb_decrypt.plaintext));

  uint32_t key_handle = read_uint32(request.payload.ecb_decrypt.key_handle);
  if (request.bcnt != (sizeof(request.payload.ecb_decrypt) + 1)) {
    response.payload.ecb_decrypt.status = THSM_STATUS_INVALID_PARAMETER;
  } else if (key_handle != THSM_TEMP_KEY_HANDLE) {
    response.payload.ecb_decrypt.status = THSM_STATUS_KEY_HANDLE_INVALID;
  } else {
    aes_state_t pt;
    aes_state_t ct;
    aes_state_t ck;

    response.payload.ecb_decrypt.status = THSM_STATUS_OK;
    memcpy(&ck, &phantom_key, sizeof(phantom_key));
    memcpy(ct.bytes, request.payload.ecb_decrypt.ciphertext, sizeof(request.payload.ecb_decrypt.ciphertext));

    /* perform decryption */
    aes_ecb_decrypt(&pt, &ct, &ck);
    memcpy(response.payload.ecb_decrypt.plaintext, pt.bytes, sizeof(pt.bytes));
  }

  /* send response */
  Serial.write((const char *)&response, response.bcnt + 1);
}

static void cmd_ecb_decrypt_cmp() {
  /* common response values */
  response.bcnt = sizeof(response.payload.ecb_decrypt_cmp) + 1;
  response.cmd = request.cmd | THSM_FLAG_RESPONSE;
  memcpy(response.payload.ecb_decrypt_cmp.key_handle, request.payload.ecb_decrypt_cmp.key_handle, sizeof(request.payload.ecb_decrypt_cmp.key_handle));

  uint32_t key_handle = read_uint32(request.payload.ecb_decrypt_cmp.key_handle);
  if (request.bcnt != (sizeof(request.payload.ecb_decrypt_cmp) + 1)) {
    response.payload.ecb_decrypt_cmp.status = THSM_STATUS_INVALID_PARAMETER;
  } else if (key_handle != THSM_TEMP_KEY_HANDLE) {
    response.payload.ecb_decrypt_cmp.status = THSM_STATUS_KEY_HANDLE_INVALID;
  } else {
    aes_state_t pt;
    aes_state_t ct;
    aes_state_t ck;

    /* copy key and ciphertext */
    memcpy(&ck, &phantom_key, sizeof(phantom_key));
    memcpy(ct.bytes, request.payload.ecb_decrypt_cmp.ciphertext, sizeof(request.payload.ecb_decrypt_cmp.ciphertext));

    /* perform decryption */
    aes_ecb_decrypt(&pt, &ct, &ck);

    /* compare plaintext */
    int match = memcmp(pt.bytes, request.payload.ecb_decrypt_cmp.plaintext, sizeof(request.payload.ecb_decrypt_cmp.plaintext));
    response.payload.ecb_decrypt_cmp.status = (match == 0) ? THSM_STATUS_OK : THSM_STATUS_MISMATCH;
  }

  /* send response */
  Serial.write((const char *)&response, response.bcnt + 1);
}

static void cmd_buffer_load() {
  /* limit offset */
  uint8_t max_offset = sizeof(request.payload.buffer_load.data) - 1;
  uint8_t offset = (request.payload.buffer_load.offset > max_offset) ? max_offset : request.payload.buffer_load.offset;

  /* offset + length must be sizeof(request.payload.buffer_load.data) */
  uint8_t max_length = sizeof(request.payload.buffer_load.data) - offset;
  uint8_t length = (request.payload.buffer_load.data_len > max_length) ? max_length : request.payload.buffer_load.data_len;

  /* set request length */
  request.bcnt = request.payload.buffer_load.data_len + 3;

  /* copy data to buffer */
  memcpy(&thsm_buffer.data[offset], request.payload.buffer_load.data, length);
  thsm_buffer.data_len = (offset > 0) ? (thsm_buffer.data_len + length) : length;

  /* prepare response */
  response.bcnt = sizeof(response.payload.buffer_load) + 1;
  response.cmd = request.cmd | THSM_FLAG_RESPONSE;
  response.payload.buffer_load.length = thsm_buffer.data_len;

  /* send response */
  Serial.write((const char *)&response, response.bcnt + 1);
}

static void cmd_buffer_random_load() {
  /* limit offset */
  uint8_t max_offset = sizeof(thsm_buffer.data) - 1;
  uint8_t offset = (request.payload.buffer_random_load.offset > max_offset) ? max_offset : request.payload.buffer_random_load.offset;

  /* offset + length must be sizeof(thsm_buffer.data) */
  uint8_t max_length = sizeof(thsm_buffer.data)  - offset;
  uint8_t length = (request.payload.buffer_random_load.length > max_length) ? max_length : request.payload.buffer_random_load.length;

  /* fill buffer with random */
  adc_rng_read(&thsm_buffer.data[offset], length);
  thsm_buffer.data_len = (offset > 0) ? (thsm_buffer.data_len + length) : length;

  /* prepare response */
  response.bcnt = sizeof(response.payload.buffer_random_load) + 1;
  response.cmd = request.cmd | THSM_FLAG_RESPONSE;
  response.payload.buffer_random_load.length = thsm_buffer.data_len;

  /* send response */
  Serial.write((const char *)&response, response.bcnt + 1);
}

static void cmd_hsm_unlock() {
  /* prepare response */
  response.bcnt = sizeof(response.payload.hsm_unlock) + 1;
  response.cmd = request.cmd | THSM_FLAG_RESPONSE;

  /* TODO: add implementation */

  /* check request byte count */
  if (request.bcnt != (sizeof(request.payload.hsm_unlock) + 1)) {
    response.payload.hsm_unlock.status = THSM_STATUS_INVALID_PARAMETER;
  } else {
    response.payload.hsm_unlock.status = THSM_STATUS_OK;
  }

  /* send response */
  Serial.write((const char *)&response, response.bcnt + 1);
}

static void cmd_key_store_decrypt() {
  /* prepare response */
  response.bcnt = sizeof(response.payload.key_store_decrypt) + 1;
  response.cmd = request.cmd | THSM_FLAG_RESPONSE;

  /* TODO: add implementation */

  /* check request byte count */
  if (request.bcnt != (sizeof(request.payload.key_store_decrypt) + 1)) {
    response.payload.key_store_decrypt.status = THSM_STATUS_INVALID_PARAMETER;
  } else {
    response.payload.key_store_decrypt.status = THSM_STATUS_OK;
  }

  /* send response */
  Serial.write((const char *)&response, response.bcnt + 1);
}

static void cmd_nonce_get() {
  /* prepare response */
  response.bcnt = sizeof(response.payload.nonce_get) + 1;
  response.cmd = request.cmd | THSM_FLAG_RESPONSE;
  response.payload.nonce_get.status = THSM_STATUS_OK;

  if (request.bcnt != (sizeof(request.payload.nonce_get) + 1)) {
    response.payload.nonce_get.status = THSM_STATUS_INVALID_PARAMETER;
  } else {
    adc_rng_read(response.payload.nonce_get.nonce, sizeof(response.payload.nonce_get.nonce));
    response.payload.nonce_get.status = THSM_STATUS_OK;
  }

  /* send response */
  Serial.write((const char *)&response, response.bcnt + 1);
}

static void cmd_aead_generate() {
  /* prepare response */
  response.bcnt = (sizeof(response.payload.aead_generate) - sizeof(request.payload.aead_generate.data)) + 1;
  response.cmd = request.cmd | THSM_FLAG_RESPONSE;
  response.payload.aead_generate.status = THSM_STATUS_OK;
  response.payload.aead_generate.data_len = 0;
  memcpy(response.payload.aead_generate.key_handle, request.payload.aead_generate.key_handle, sizeof(request.payload.aead_generate.key_handle));
  memcpy(response.payload.aead_generate.nonce, request.payload.aead_generate.nonce, sizeof(request.payload.aead_generate.nonce));
  memset(response.payload.aead_generate.data, 0, sizeof(response.payload.aead_generate.data));

  /* get key handle */
  uint32_t key_handle = read_uint32(request.payload.aead_generate.key_handle);

  if (request.bcnt > (sizeof(request.payload.aead_generate) + 1)) {
    response.payload.aead_generate.status = THSM_STATUS_INVALID_PARAMETER;
  } else if (key_handle != 0xffffffff) {
    response.payload.aead_generate.status = THSM_STATUS_KEY_HANDLE_INVALID;
  } else if (request.payload.aead_generate.data_len < 1) {
    response.payload.aead_generate.status = THSM_STATUS_INVALID_PARAMETER;
  } else if (request.payload.aead_generate.data_len > sizeof(request.payload.aead_generate.data)) {
    response.payload.aead_generate.status = THSM_STATUS_INVALID_PARAMETER;
  } else {
    /* generate nonce */
    if (memcmp(response.payload.aead_generate.nonce, null_nonce, sizeof(null_nonce)) == 0) {
      adc_rng_read(response.payload.aead_generate.nonce, sizeof(response.payload.aead_generate.nonce));
    }

    /* FIXME load proper key */
    aes_ccm_generate(response.payload.aead_generate.data,
                     request.payload.aead_generate.data,
                     request.payload.aead_generate.data_len,
                     request.payload.aead_generate.key_handle,
                     &phantom_key,
                     request.payload.aead_generate.nonce);

    response.payload.aead_generate.data_len = request.payload.aead_generate.data_len + 8;
    response.bcnt += response.payload.aead_generate.data_len;
    response.payload.aead_generate.status = THSM_STATUS_OK;
  }

  /* send response */
  Serial.write((const char *)&response, response.bcnt + 1);
}


//--------------------------------------------------------------------------------------------------
// Helper
//--------------------------------------------------------------------------------------------------
static uint32_t read_uint32(uint8_t *s) {
  return (s[0] << 24) | (s[1] << 16) | (s[2] << 8) | s[3];
}

static void write_uint32(uint8_t *d, uint32_t v) {
  *d++ = (v >> 24);
  *d++ = (v >> 16);
  *d++ = (v >> 8);
  *d++ = (v >> 0);
}

//--------------------------------------------------------------------------------------------------
// PRNG
//--------------------------------------------------------------------------------------------------
static uint8_t adc_read()
{
  int ret = ADC_ERROR_VALUE;
  while (ret == ADC_ERROR_VALUE) {
    ret = adc->analogRead(A9, ADC_0);
  }
  return ret;
}

static uint32_t adc_rng_step() {
  uint8_t buffer[16];

  /* fill buffer */
  for (int i = 0; i < 16; i++) {
    buffer[i] = adc_read();
  }

  return CRC32.crc32(buffer, sizeof(buffer));
}

static void adc_rng_read(uint8_t *p_buffer, uint32_t len)
{
  word_t data;
  uint32_t idx = 4;

  while (len--)
  {
    if (idx == 4)
    {
      data.words = adc_rng_step();
      idx = 0;
    }

    *p_buffer++ = data.bytes[idx++];
  }
}

//--------------------------------------------------------------------------------------------------
// AES-ECB block cipher
//--------------------------------------------------------------------------------------------------
static void aes_ecb_encrypt(aes_state_t *ct, aes_state_t *pt, aes_state_t *ck) {
  aes_subkeys_t sk;

  /* derive sub-keys */
  aes_init(&sk, ck);

  /* encrypt */
  aes_encrypt(ct, pt, &sk);

  /* cleanup subkeys */
  memset(&sk, 0, sizeof(sk));
}

static void aes_ecb_decrypt(aes_state_t *pt, aes_state_t *ct, aes_state_t *ck) {
  aes_subkeys_t sk;

  /* derive sub-keys */
  aes_init(&sk, ck);

  /* decrypt */
  aes_decrypt(pt, ct, &sk);

  /* cleanup subkeys */
  memset(&sk, 0, sizeof(sk));
}

static void aes_init(aes_subkeys_t *sk, aes_state_t *ck) {
  aes_state_t *src = &(sk->keys[0]);
  aes_state_t *dst = &(sk->keys[1]);

  /* backup to temporary state */
  aes_state_copy(src, ck);

  /* derive subkeys */
  for (int i = 1; i < 11; i++, src++, dst++) {
    dst->bytes[ 0] = src->bytes[ 0] ^ te[src->bytes[13]] ^ rcons[i];
    dst->bytes[ 1] = src->bytes[ 1] ^ te[src->bytes[14]];
    dst->bytes[ 2] = src->bytes[ 2] ^ te[src->bytes[15]];
    dst->bytes[ 3] = src->bytes[ 3] ^ te[src->bytes[12]];
    dst->bytes[ 4] = src->bytes[ 4] ^ dst->bytes[ 0];
    dst->bytes[ 5] = src->bytes[ 5] ^ dst->bytes[ 1];
    dst->bytes[ 6] = src->bytes[ 6] ^ dst->bytes[ 2];
    dst->bytes[ 7] = src->bytes[ 7] ^ dst->bytes[ 3];
    dst->bytes[ 8] = src->bytes[ 8] ^ dst->bytes[ 4];
    dst->bytes[ 9] = src->bytes[ 9] ^ dst->bytes[ 5];
    dst->bytes[10] = src->bytes[10] ^ dst->bytes[ 6];
    dst->bytes[11] = src->bytes[11] ^ dst->bytes[ 7];
    dst->bytes[12] = src->bytes[12] ^ dst->bytes[ 8];
    dst->bytes[13] = src->bytes[13] ^ dst->bytes[ 9];
    dst->bytes[14] = src->bytes[14] ^ dst->bytes[10];
    dst->bytes[15] = src->bytes[15] ^ dst->bytes[11];
  }
}

static void aes_encrypt(aes_state_t *ct, aes_state_t *pt, aes_subkeys_t *sk) {
  aes_state_t tmp;

  aes_state_t *key = &(sk->keys[0]);
  aes_state_xor(&tmp, pt, key);

  for (int i = 0; i < 9; i++) {
    aes_encrypt_step(&tmp, ++key);
  }
  aes_encrypt_final(ct, &tmp, ++key);
}

static void aes_decrypt(aes_state_t *pt, aes_state_t *ct, aes_subkeys_t *sk) {
  aes_state_t tmp;

  aes_state_t *key = &(sk->keys[10]);
  aes_state_xor(&tmp, ct, key);

  for (int i = 0; i < 9; i++)
  {
    aes_decrypt_step(&tmp, --key);
  }
  aes_decrypt_final(pt, &tmp, --key);
}

static void aes_encrypt_step(aes_state_t *s, aes_state_t *k) {
  aes_state_t t;

  /* copy to temporary state */
  aes_state_copy(&t, s);

  /* shift-row, substitute, mix-column & add-round-key */
  s->words[0] = te0[t.bytes[ 0]] ^ te1[t.bytes[ 5]] ^ te2[t.bytes[10]] ^ te3[t.bytes[15]] ^ k->words[0];
  s->words[1] = te0[t.bytes[ 4]] ^ te1[t.bytes[ 9]] ^ te2[t.bytes[14]] ^ te3[t.bytes[ 3]] ^ k->words[1];
  s->words[2] = te0[t.bytes[ 8]] ^ te1[t.bytes[13]] ^ te2[t.bytes[ 2]] ^ te3[t.bytes[ 7]] ^ k->words[2];
  s->words[3] = te0[t.bytes[12]] ^ te1[t.bytes[ 1]] ^ te2[t.bytes[ 6]] ^ te3[t.bytes[11]] ^ k->words[3];
}

static void aes_decrypt_step(aes_state_t *s, aes_state_t *k) {
  aes_state_t t;

  /* inverse shift-row, inverse-substitution and add-round-key */
  t.bytes[ 0] = td[s->bytes[ 0]] ^ k->bytes[0];
  t.bytes[ 1] = td[s->bytes[13]] ^ k->bytes[1];
  t.bytes[ 2] = td[s->bytes[10]] ^ k->bytes[2];
  t.bytes[ 3] = td[s->bytes[ 7]] ^ k->bytes[3];
  t.bytes[ 4] = td[s->bytes[ 4]] ^ k->bytes[4];
  t.bytes[ 5] = td[s->bytes[ 1]] ^ k->bytes[5];
  t.bytes[ 6] = td[s->bytes[14]] ^ k->bytes[6];
  t.bytes[ 7] = td[s->bytes[11]] ^ k->bytes[7];
  t.bytes[ 8] = td[s->bytes[ 8]] ^ k->bytes[8];
  t.bytes[ 9] = td[s->bytes[ 5]] ^ k->bytes[9];
  t.bytes[10] = td[s->bytes[ 2]] ^ k->bytes[10];
  t.bytes[11] = td[s->bytes[15]] ^ k->bytes[11];
  t.bytes[12] = td[s->bytes[12]] ^ k->bytes[12];
  t.bytes[13] = td[s->bytes[ 9]] ^ k->bytes[13];
  t.bytes[14] = td[s->bytes[ 6]] ^ k->bytes[14];
  t.bytes[15] = td[s->bytes[ 3]] ^ k->bytes[15];

  /* inverse mix-column */
  s->words[0] = td0[t.bytes[ 0]] ^ td1[t.bytes[ 1]] ^ td2[t.bytes[ 2]] ^ td3[t.bytes[ 3]];
  s->words[1] = td0[t.bytes[ 4]] ^ td1[t.bytes[ 5]] ^ td2[t.bytes[ 6]] ^ td3[t.bytes[ 7]];
  s->words[2] = td0[t.bytes[ 8]] ^ td1[t.bytes[ 9]] ^ td2[t.bytes[10]] ^ td3[t.bytes[11]];
  s->words[3] = td0[t.bytes[12]] ^ td1[t.bytes[13]] ^ td2[t.bytes[14]] ^ td3[t.bytes[15]];
}

static void aes_encrypt_final(aes_state_t *c, aes_state_t *s, aes_state_t *k) {
  aes_state_t t;

  /* final shift-row & substitute */
  t.bytes[ 0] = te[s->bytes[ 0]];
  t.bytes[ 1] = te[s->bytes[ 5]];
  t.bytes[ 2] = te[s->bytes[10]];
  t.bytes[ 3] = te[s->bytes[15]];
  t.bytes[ 4] = te[s->bytes[ 4]];
  t.bytes[ 5] = te[s->bytes[ 9]];
  t.bytes[ 6] = te[s->bytes[14]];
  t.bytes[ 7] = te[s->bytes[ 3]];
  t.bytes[ 8] = te[s->bytes[ 8]];
  t.bytes[ 9] = te[s->bytes[13]];
  t.bytes[10] = te[s->bytes[ 2]];
  t.bytes[11] = te[s->bytes[ 7]];
  t.bytes[12] = te[s->bytes[12]];
  t.bytes[13] = te[s->bytes[ 1]];
  t.bytes[14] = te[s->bytes[ 6]];
  t.bytes[15] = te[s->bytes[11]];

  /* final add round key */
  aes_state_xor(c, &t, k);

  /* cleanup temporary state */
  memset(&t, 0, sizeof(t));
}

static void aes_decrypt_final(aes_state_t *p, aes_state_t *s, aes_state_t *k) {
  p->bytes[ 0] = td[s->bytes[ 0]] ^ k->bytes[ 0];
  p->bytes[ 1] = td[s->bytes[13]] ^ k->bytes[ 1];
  p->bytes[ 2] = td[s->bytes[10]] ^ k->bytes[ 2];
  p->bytes[ 3] = td[s->bytes[ 7]] ^ k->bytes[ 3];
  p->bytes[ 4] = td[s->bytes[ 4]] ^ k->bytes[ 4];
  p->bytes[ 5] = td[s->bytes[ 1]] ^ k->bytes[ 5];
  p->bytes[ 6] = td[s->bytes[14]] ^ k->bytes[ 6];
  p->bytes[ 7] = td[s->bytes[11]] ^ k->bytes[ 7];
  p->bytes[ 8] = td[s->bytes[ 8]] ^ k->bytes[ 8];
  p->bytes[ 9] = td[s->bytes[ 5]] ^ k->bytes[ 9];
  p->bytes[10] = td[s->bytes[ 2]] ^ k->bytes[10];
  p->bytes[11] = td[s->bytes[15]] ^ k->bytes[11];
  p->bytes[12] = td[s->bytes[12]] ^ k->bytes[12];
  p->bytes[13] = td[s->bytes[ 9]] ^ k->bytes[13];
  p->bytes[14] = td[s->bytes[ 6]] ^ k->bytes[14];
  p->bytes[15] = td[s->bytes[ 3]] ^ k->bytes[15];

  /* cleanup temporary state */
  memset(s, 0, sizeof(aes_state_t));
}

static void aes_state_copy(aes_state_t *dst, aes_state_t *src) {
  dst->words[0] = src->words[0];
  dst->words[1] = src->words[1];
  dst->words[2] = src->words[2];
  dst->words[3] = src->words[3];
}

static void aes_state_xor(aes_state_t *dst, aes_state_t *src1, aes_state_t *src2) {
  dst->words[0] = src1->words[0] ^ src2->words[0];
  dst->words[1] = src1->words[1] ^ src2->words[1];
  dst->words[2] = src1->words[2] ^ src2->words[2];
  dst->words[3] = src1->words[3] ^ src2->words[3];
}

//--------------------------------------------------------------------------------------------------
// AES-CCM block cipher
//--------------------------------------------------------------------------------------------------
static uint8_t aes_ccm_generate(uint8_t *ct, uint8_t *pt, uint8_t len, uint8_t *kh, aes_state_t *ck, uint8_t *nonce) {
  aes_subkeys_t sk;
  aes_state_t tmp;
  aes_state_t mac_in, mac_out;
  aes_state_t cipher_in, cipher_out;

  /* set MAC IV */
  memset(&mac_in, 0, sizeof(mac_in));
  mac_in.bytes[0] = 0x19; /* 8 bytes mac and 2 bytes counter */
  memcpy(&(mac_in.bytes[1]), kh,    4);
  memcpy(&(mac_in.bytes[5]), nonce, 6);
  mac_in.bytes[15] = len;

  /* set cipher IV */
  memset(&cipher_in, 0, sizeof(cipher_in));
  cipher_in.bytes[0] = 0x01; /* 2 bytes counter */
  memcpy(&(cipher_in.bytes[1]), kh,    4);
  memcpy(&(cipher_in.bytes[5]), nonce, 6);
  cipher_in.bytes[15] = 1;

  /* derive subkeys */
  aes_init(&sk, ck);

  /* derive sub-keys */
  uint8_t remaining = len;
  while (remaining-- > 0) {
    /* load plaintext */
    uint8_t step = (remaining > 16) ? 16 : remaining;
    for (int i = 0; i < sizeof(tmp); i++) {
      tmp.bytes[i] = (i < step) ? *pt++ : 0;
    }

    /* perform encryption */
    aes_encrypt(&mac_out, &mac_in, &sk);
    aes_encrypt(&cipher_out, &cipher_in, &sk);

    /* xor mac stream with plaintext */
    mac_in.words[1] = mac_out.words[0] ^ tmp.words[0];
    mac_in.words[1] = mac_out.words[1] ^ tmp.words[1];
    mac_in.words[2] = mac_out.words[2] ^ tmp.words[2];
    mac_in.words[3] = mac_out.words[3] ^ tmp.words[3];

    /* xor cipher stream with plaintext */
    for (int j = 0; j < 16; j++) {
      *ct++ = cipher_out.bytes[j] ^ tmp.bytes[j];
    }

    if (cipher_in.bytes[15] == 0xff) {
      cipher_in.bytes[15] = 0;
      cipher_in.bytes[14]++;
    } else {
      cipher_in.bytes[15]++;
    }

    /* update counter */
    remaining -= step;
  }

  /* set MAC iv */
  memset(&mac_in, 0, sizeof(mac_in));
  mac_in.bytes[0] = 0x19; /* 8 bytes mac and 2 bytes counter */
  memcpy(&(mac_in.bytes[1]), kh,    4);
  memcpy(&(mac_in.bytes[5]), nonce, 6);

  /* perform encryption */
  aes_encrypt(&tmp, &mac_in, &sk);

  /* append mac mac to ciphertext result */
  for (int j = 0; j < 8; j++) {
    *ct++ = mac_out.bytes[j] ^ tmp.bytes[j];
  }
}

//--------------------------------------------------------------------------------------------------
// HMAC-SHA1
//--------------------------------------------------------------------------------------------------
static void hmac_sha1_init(hmac_sha1_ctx_t *ctx, uint8_t *key, uint8_t len)
{
  /* clear and initialize context */
  memset(ctx, 0, sizeof(hmac_sha1_ctx_t));

  if (len > sizeof(ctx->key))
  {
    sha1_init(&(ctx->hash));
    sha1_update(&(ctx->hash), key, len);
    sha1_final(&(ctx->hash), ctx->key);
  }
  else
  {
    memcpy(ctx->key, key, len);
  }

  /* xor key with ipad */
  uint8_t tmp[SHA1_BLOCK_SIZE_BYTES];
  for (int i = 0; i < sizeof(tmp); i++)
  {
    tmp[i] = 0x36 ^ ctx->key[i];
  }

  /* init and update hash */
  sha1_init(&(ctx->hash));
  sha1_update(&(ctx->hash), tmp, sizeof(tmp));
}

static void hmac_sha1_update(hmac_sha1_ctx_t *ctx, uint8_t *data, uint8_t len)
{
  /* update hash */
  sha1_update(&(ctx->hash), data, len);
}

static void hmac_sha1_final(hmac_sha1_ctx_t *ctx, uint8_t *mac)
{
  uint8_t digest[SHA1_DIGEST_SIZE_BYTES];
  uint8_t tmp[SHA1_BLOCK_SIZE_BYTES];

  /* finalize hash */
  sha1_final(&(ctx->hash), digest);

  /* xor key with opad */
  for (int i = 0; i < sizeof(tmp); i++)
  {
    tmp[i] = 0x5c ^ ctx->key[i];
  }

  /* reinitialize hash context */
  sha1_init(&(ctx->hash));
  sha1_update(&(ctx->hash), tmp, sizeof(tmp));
  sha1_update(&(ctx->hash), digest, sizeof(digest));
  sha1_final(&(ctx->hash), mac);
}

//--------------------------------------------------------------------------------------------------
// SHA1
//--------------------------------------------------------------------------------------------------
static void sha1_init(sha1_ctx_t *ctx)
{
  memset(ctx, 0, sizeof(sha1_ctx_t));
  ctx->hashes[0] = 0x67452301;
  ctx->hashes[1] = 0xefcdab89;
  ctx->hashes[2] = 0x98badcfe;
  ctx->hashes[3] = 0x10325476;
  ctx->hashes[4] = 0xc3d2e1f0;
}

static void sha1_update(sha1_ctx_t *state, uint8_t *data, uint8_t length)
{
  /* update total length */
  state->msg_length += length;

  while (length > 0)
  {
    uint32_t written = state->buffer.length;
    if (written < sizeof(state->buffer.bytes))
    {
      uint32_t max = (sizeof(state->buffer.bytes) - written);
      uint32_t step = (length > max) ? max : length;
      memcpy(&state->buffer.bytes[written], data, step);

      data += step;
      length -= step;
      written += step;
      state->buffer.length += step;
    }

    if (written >= sizeof(state->buffer.bytes))
    {
      sha1_step(state);
    }
  }
}

static void sha1_final(sha1_ctx_t *ctx, uint8_t *digest)
{
  uint32_t written = ctx->buffer.length;

  /* append padding */
  ctx->buffer.bytes[written] = 0x80;
  memset(&ctx->buffer.bytes[written + 1], 0, (sizeof(ctx->buffer.bytes) - (written + 1)));

  if (written > (sizeof(ctx->buffer.bytes) - 9))
  {
    sha1_step(ctx);
  }

  /* append length in bits */
  uint8_t *ptr = &ctx->buffer.bytes[sizeof(ctx->buffer.bytes) - sizeof(uint64_t)];
  uint64_t msg_length = ctx->msg_length << 3;
  *ptr++ = (uint8_t) (msg_length >> 56);
  *ptr++ = (uint8_t) (msg_length >> 48);
  *ptr++ = (uint8_t) (msg_length >> 40);
  *ptr++ = (uint8_t) (msg_length >> 32);
  *ptr++ = (uint8_t) (msg_length >> 24);
  *ptr++ = (uint8_t) (msg_length >> 16);
  *ptr++ = (uint8_t) (msg_length >> 8);
  *ptr++ = (uint8_t) (msg_length);

  /* run last round */
  sha1_step(ctx);

  for (int i = 0; i < SHA1_DIGEST_SIZE_WORDS; i++)
  {
    *digest++ = (uint8_t) (ctx->hashes[i] >> 24);
    *digest++ = (uint8_t) (ctx->hashes[i] >> 16);
    *digest++ = (uint8_t) (ctx->hashes[i] >> 8);
    *digest++ = (uint8_t) (ctx->hashes[i]);
  }
}

static void sha1_step(sha1_ctx_t *ctx)
{

  uint32_t words[SHA1_BLOCK_SIZE_WORDS];
  uint32_t a, b, c, d, e;

  /* load block */
  uint8_t *p2 = ctx->buffer.bytes;
  for (int i = 0; i < SHA1_BLOCK_SIZE_WORDS; i++)
  {
    uint32_t tmp = 0;
    tmp |= *p2++ << 24;
    tmp |= *p2++ << 16;
    tmp |= *p2++ << 8;
    tmp |= *p2++ << 0;
    words[i] = tmp;
  }

  /* load hash */
  a = ctx->hashes[0];
  b = ctx->hashes[1];
  c = ctx->hashes[2];
  d = ctx->hashes[3];
  e = ctx->hashes[4];

  for (uint32_t i = 0; i < 80; i++)
  {
    uint32_t w;

    uint32_t t = (i < 16) ? words[i] : ROTL_1((ctx->words[i - 3] ^ ctx->words[i - 8] ^ ctx->words[i - 14] ^ ctx->words[i - 16]));
    ctx->words[i] = t;

    if (i < 20)
    {
      w = ROTL_5(a) + ((b & c) | ((~b) & d)) + e + t + 0x5a827999;
    }
    else if (i < 40)
    {
      w = ROTL_5(a) + (b ^ c ^ d) + e + t + 0x6ed9eba1;
    }
    else if (i < 60)
    {
      w = ROTL_5(a) + ((b & c) | (b & d) | (c & d)) + e + t + 0x8f1bbcdc;
    }
    else
    {
      w = ROTL_5(a) + (b ^ c ^ d) + e + t + 0xca62c1d6;
    }

    e = d;
    d = c;
    c = ROTL_30(b);
    b = a;
    a = w;
  }

  /* store hash */
  ctx->hashes[0] += a;
  ctx->hashes[1] += b;
  ctx->hashes[2] += c;
  ctx->hashes[3] += d;
  ctx->hashes[4] += e;

  /* clear buffer */
  memset(ctx->buffer.bytes, 0, sizeof(ctx->buffer.bytes));
  ctx->buffer.length = 0;
}
