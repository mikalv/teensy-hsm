#ifndef __AES_CBC_H__
#define __AES_CBC_H__

#include "aes.h"
#include "buffer.h"

class AESCBC
{
public:
    AESCBC();
    int32_t encrypt(buffer_t &ciphertext, const buffer_t &plaintext, const aes_state_t &key, const aes_state_t &iv);
    int32_t decrypt(buffer_t &plaintext, const buffer_t &ciphertext, const aes_state_t &key, const aes_state_t &iv);
private:
    void state_xor(aes_state_t &dst, const aes_state_t &src1, const aes_state_t &src2);
    void state_copy(aes_state_t &dst, const aes_state_t &src);
};

#endif
