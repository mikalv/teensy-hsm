#ifndef __SIZES_H__
#define __SIZES_H__

#define THSM_KEY_FLAGS_SIZE         4
#define THSM_OTP_SIZE              16 // Size of OTP
#define THSM_BLOCK_SIZE            16 // Size of block operations
#define THSM_KEY_SIZE              16 // Size of key
#define THSM_MAX_KEY_SIZE          32 // Max size of CCMkey

#define THSM_CCM_CTR_SIZE           2 // Sizeof of AES CCM counter field
#define THSM_AEAD_MAX_SIZE       (THSM_DATA_BUF_SIZE + THSM_AEAD_MAC_SIZE) // Max size of an AEAD block
#define THSM_SHA1_HASH_SIZE        20 // 160-bit SHA1 hash size

#define THSM_SYSTEM_ID_SIZE        12
#define THSM_OTP_DELTA_MAX         32 // max difference of OTP delta

#endif
