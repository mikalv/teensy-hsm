#ifndef __SIZES_H__
#define __SIZES_H__

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
#define THSM_HMAC_RESET          0x01
#define THSM_HMAC_FINAL          0x02
#define THSM_HMAC_SHA1_TO_BUFFER 0x04
#define THSM_SYSTEM_ID_SIZE        12
#define THSM_PUBLIC_ID_SIZE         6
#define THSM_DB_KEY_ENTRIES        32
#define THSM_DB_SECRET_ENTRIES     32
#define THSM_AEAD_SIZE           (THSM_KEY_SIZE + THSM_PUBLIC_ID_SIZE + THSM_AEAD_MAC_SIZE)
#define THSM_OTP_DELTA_MAX         32 // max difference of OTP delta

#endif
