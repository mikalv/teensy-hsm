#ifndef __AES_CCM_H__
#define __AES_CCM_H__

#include "aes.h"
#include "buffer.h"

#define AES_CCM_MAC_SIZE_BITS       64
#define AES_CCM_MAC_SIZE_BYTES      (AES_CCM_MAC_SIZE_BITS / 8)
#define AES_CCM_MAC_SIZE_WORDS      (AES_CCM_MAC_SIZE_BYTES / sizeof(uint32_t))
#define AES_CCM_NONCE_SIZE_BITS     48
#define AES_CCM_NONCE_SIZE_BYTES    (AES_CCM_NONCE_SIZE_BITS / 8)
#define AES_CCM_NONCE_SIZE_WORDS    (AES_CCM_NONCE_SIZE_BYTES / sizeof(uint32_t))

typedef struct {
    uint8_t bytes[AES_CCM_NONCE_SIZE_BYTES];
} ccm_nonce_t;

class Counter {
public:
    Counter(uint32_t key_handle, const ccm_nonce_t &nonce);
    void encode(aes_state_t &out);
private:
    uint8_t flags;
    uint16_t counter;
    uint32_t key_handle;
    ccm_nonce_t nonce;
};

class Iv {
public:
    Iv(uint32_t key_handle, const ccm_nonce_t &nonce, uint16_t length);
    void encode(aes_state_t &out);
private:
    uint8_t flags;
    uint16_t length;
    uint32_t key_handle;
    ccm_nonce_t nonce;
};

class AESCCM {
public:
    int32_t encrypt(buffer_t &ciphertext, const buffer_t &plaintext, const aes_state_t &key, const uint32_t key_handle,
            const ccm_nonce_t &nonce);
    int32_t decrypt(buffer_t &plaintext, const buffer_t &ciphertext, const aes_state_t &key, const uint32_t key_handle,
            const ccm_nonce_t &nonce);
};

#endif
