#ifndef __COMMANDS_H__
#define __COMMANDS_H__

//------------------------------------------------------------------------------
// Command Identifier
//------------------------------------------------------------------------------
#define THSM_CMD_NULL                       0x00
#define THSM_CMD_AEAD_GENERATE              0x01
#define THSM_CMD_BUFFER_AEAD_GENERATE       0x02
#define THSM_CMD_RANDOM_AEAD_GENERATE       0x03
#define THSM_CMD_AEAD_DECRYPT_CMP           0x04
#define THSM_CMD_DB_AEAD_STORE              0x05
#define THSM_CMD_AEAD_OTP_DECODE            0x06
#define THSM_CMD_DB_OTP_VALIDATE            0x07
#define THSM_CMD_DB_AEAD_STORE2             0x08
#define THSM_CMD_AES_ECB_BLOCK_ENCRYPT      0x0d
#define THSM_CMD_AES_ECB_BLOCK_DECRYPT      0x0e
#define THSM_CMD_AES_ECB_BLOCK_DECRYPT_CMP  0x0f
#define THSM_CMD_HMAC_SHA1_GENERATE         0x10
#define THSM_CMD_TEMP_KEY_LOAD              0x11
#define THSM_CMD_BUFFER_LOAD                0x20
#define THSM_CMD_BUFFER_RANDOM_LOAD         0x21
#define THSM_CMD_NONCE_GET                  0x22
#define THSM_CMD_ECHO                       0x23
#define THSM_CMD_RANDOM_GENERATE            0x24
#define THSM_CMD_RANDOM_RESEED              0x25
#define THSM_CMD_SYSTEM_INFO_QUERY          0x26
#define THSM_CMD_HSM_UNLOCK                 0x28
#define THSM_CMD_KEY_STORE_DECRYPT          0x29
#define THSM_CMD_MONITOR_EXIT               0x7f

//------------------------------------------------------------------------------
// Response Flags
//------------------------------------------------------------------------------
#define THSM_FLAG_RESPONSE                  0x80

#endif
