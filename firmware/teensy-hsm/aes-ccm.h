#ifndef __AES_CCM_H__
#define __AES_CCM_H__

#include "aes.h"

#define AES_CCM_MAC_SIZE_BITS       64
#define AES_CCM_MAC_SIZE_BYTES      (AES_CCM_MAC_SIZE_BITS / 8)
#define AES_CCM_MAC_SIZE_WORDS      (AES_CCM_MAC_SIZE_BYTES / sizeof(uint32_t))
#define AES_CCM_NONCE_SIZE_BITS     48
#define AES_CCM_NONCE_SIZE_BYTES    (AES_CCM_NONCE_SIZE_BITS / 8)
#define AES_CCM_NONCE_SIZE_WORDS    (AES_CCM_NONCE_SIZE_BYTES / sizeof(uint32_t))

class AESCCM
{
public:
    void encrypt(uint32_t key_handle);
private:
};
#endif
