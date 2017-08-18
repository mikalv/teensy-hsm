#ifndef __COMMANDS_H__
#define __COMMANDS_H__

#include <stdint.h>
#include "flags.h"
#include "buffer.h"
#include "sizes.h"
#include "storage.h"
#include "aes-drbg.h"

//------------------------------------------------------------------------------
// Response Flags
//------------------------------------------------------------------------------
#define THSM_FLAG_RESPONSE                  0x80

#define THSM_STATUS_OK                      0x80
#define THSM_STATUS_KEY_HANDLE_INVALID      0x81
#define THSM_STATUS_AEAD_INVALID            0x82
#define THSM_STATUS_OTP_INVALID             0x83
#define THSM_STATUS_OTP_REPLAY              0x84
#define THSM_STATUS_ID_DUPLICATE            0x85
#define THSM_STATUS_ID_NOT_FOUND            0x86
#define THSM_STATUS_DB_FULL                 0x87
#define THSM_STATUS_MEMORY_ERROR            0x88
#define THSM_STATUS_FUNCTION_DISABLED       0x89
#define THSM_STATUS_KEY_STORAGE_LOCKED      0x8a
#define THSM_STATUS_MISMATCH                0x8b
#define THSM_STATUS_INVALID_PARAMETER       0x8c

#define THSM_MAX_PKT_SIZE        0x60 // Max size of a packet (excluding command byte)

typedef struct
{
    uint8_t bytes[THSM_MAX_PKT_SIZE];
    uint32_t length;
} packet_t;

class Commands
{
public:
    Commands();
    int32_t process(uint8_t cmd, packet_t &response, const packet_t &request);
private:
    int32_t null(packet_t &response, const packet_t &request);
    int32_t aead_generate(packet_t &response, const packet_t &request);
    int32_t buffer_aead_generate(packet_t &response, const packet_t &request);
    int32_t random_aead_generate(packet_t &response, const packet_t &request);
    int32_t aead_decrypt_cmp(packet_t &response, const packet_t &request);
    int32_t db_aead_store(packet_t &response, const packet_t &request);
    int32_t aead_otp_decode(packet_t &response, const packet_t &request);
    int32_t db_otp_validate(packet_t &response, const packet_t &request);
    int32_t db_aead_store2(packet_t &response, const packet_t &request);
    int32_t aes_ecb_block_encrypt(packet_t &response, const packet_t &request);
    int32_t aes_ecb_block_decrypt(packet_t &response, const packet_t &request);
    int32_t aes_ecb_block_decrypt_cmp(packet_t &response, const packet_t &request);
    int32_t hmac_sha1_generate(packet_t &response, const packet_t &request);
    int32_t temp_key_load(packet_t &response, const packet_t &request);
    int32_t buffer_load(packet_t &response, const packet_t &request);
    int32_t buffer_random_load(packet_t &response, const packet_t &request);
    int32_t nonce_get(packet_t &response, const packet_t &request);
    int32_t echo(packet_t &response, const packet_t &request);
    int32_t random_generate(packet_t &response, const packet_t &request);
    int32_t random_reseed(packet_t &response, const packet_t &request);
    int32_t system_info_query(packet_t &response, const packet_t &request);
    int32_t hsm_unlock(packet_t &response, const packet_t &request);
    int32_t key_store_decrypt(packet_t &response, const packet_t &request);
    int32_t monitor_exit(packet_t &response, const packet_t &request);
    Flags flags;
    Storage storage;
    AESDRBG drbg;
};
#endif
