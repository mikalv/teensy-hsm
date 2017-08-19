#ifndef __AES_CBC_H__
#define __AES_CBC_H__

#include "aes.h"

class AESCBC {
public:
    AESCBC();
    ~AESCBC();
    void init(const aes_state_t &key, const aes_state_t &iv);
    void encrypt(aes_state_t &ciphertext, const aes_state_t &plaintext);
    void encrypt(uint8_t *p_ciphertext, const uint8_t *p_plaintext, uint32_t plaintext_length, const uint8_t *p_key, const uint8_t *p_iv);
    void decrypt(aes_state_t &plaintext, const aes_state_t &ciphertext);
    void decrypt(uint8_t *p_plaintext, const uint8_t *p_ciphertext, uint32_t ciphertext_length, const uint8_t *p_key, const uint8_t *p_iv);
    void reset();
    void clear();
private:
    AES ctx;
    aes_state_t iv, tmp_enc, tmp_dec;
};

#endif
