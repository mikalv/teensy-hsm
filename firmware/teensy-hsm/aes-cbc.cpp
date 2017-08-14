#include <string.h>
#include "aes-cbc.h"

AESCBC::AESCBC()
{
}

int32_t AESCBC::encrypt(buffer_t &ciphertext, const buffer_t &plaintext, const aes_state_t &key, const aes_state_t &iv)
{
    if (!plaintext.bytes || !ciphertext.bytes || !plaintext.length || !ciphertext.length)
    {
        return 0;
    }
    else if ((plaintext.length != ciphertext.length) || (ciphertext.length % AES_BLOCK_SIZE_BYTES))
    {
        return -1;
    }

    int32_t written = 0;
    uint8_t *p_in = plaintext.bytes;
    uint8_t *p_out = ciphertext.bytes;
    aes_state_t pt, ct;
    AES aes = AES(key);

    AES::state_copy(ct, iv);
    uint32_t blocks = plaintext.length / AES_BLOCK_SIZE_BYTES;
    for (uint32_t i = 0; i < blocks; i++)
    {
        memcpy(pt.bytes, p_in, sizeof(pt.bytes));
        AES::state_xor(pt, pt, ct);
        aes.encrypt(ct, pt);
        memcpy(p_out, ct.bytes, sizeof(ct.bytes));

        p_in += AES_BLOCK_SIZE_BYTES;
        p_out += AES_BLOCK_SIZE_BYTES;
        written += AES_BLOCK_SIZE_BYTES;
    }

    return written;

}

int32_t AESCBC::decrypt(buffer_t &plaintext, const buffer_t &ciphertext, const aes_state_t &key, const aes_state_t &iv)
{
    if (!plaintext.bytes || !ciphertext.bytes || !plaintext.length || !ciphertext.length)
    {
        return 0;
    }
    else if ((plaintext.length != ciphertext.length) || (ciphertext.length % AES_BLOCK_SIZE_BYTES))
    {
        return -1;
    }

    int32_t written = 0;
    uint8_t *p_in = ciphertext.bytes;
    uint8_t *p_out = plaintext.bytes;
    aes_state_t pt, ct, tmp;
    AES aes = AES(key);

    AES::state_copy(tmp, iv);
    uint32_t blocks = plaintext.length / AES_BLOCK_SIZE_BYTES;
    for (uint32_t i = 0; i < blocks; i++)
    {
        memcpy(ct.bytes, p_in, sizeof(ct.bytes));
        aes.decrypt(pt, ct);
        AES::state_xor(pt, pt, tmp);
        memcpy(p_out, pt.bytes, sizeof(pt.bytes));
        AES::state_copy(tmp, ct);

        p_in += AES_BLOCK_SIZE_BYTES;
        p_out += AES_BLOCK_SIZE_BYTES;
        written += AES_BLOCK_SIZE_BYTES;
    }

    return written;
}
