#ifndef __AES_ECB_H__
#define __AES_ECB_H__

#include "aes.h"
#include "buffer.h"

class AESECB
{
public:
    AESECB();
    int32_t encrypt(buffer_t &ciphertext, const buffer_t &plaintext, const aes_key_t &key);
    int32_t decrypt(buffer_t &plaintext, const buffer_t &ciphertext, const aes_key_t &key);
};
#endif
