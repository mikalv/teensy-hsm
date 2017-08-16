#ifndef __AES_CBC_H__
#define __AES_CBC_H__

#include "aes.h"

class AESCBC {
public:
    AESCBC(const aes_state_t &key, const aes_state_t &iv);
    ~AESCBC();
    void encrypt(aes_state_t &ciphertext, const aes_state_t &plaintext);
    void decrypt(aes_state_t &plaintext, const aes_state_t &ciphertext);
    void reset();
    void clear();
private:
    AES ctx;
    aes_state_t iv, tmp_enc, tmp_dec;
};

#endif
