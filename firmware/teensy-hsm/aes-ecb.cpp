#include <string.h>
#include "aes-ecb.h"

AESECB::AESECB()
{
}

int32_t AESECB::encrypt(buffer_t &ciphertext, const buffer_t &plaintext, const aes_key_t &key)
{
    if ((plaintext.bytes == NULL) || (ciphertext.bytes == NULL))
    {
        return 0;
    }
    else if ((plaintext.length != ciphertext.length) || (plaintext.length % AES_BLOCK_SIZE_BYTES))
    {
        return -1;
    }

    int32_t written = 0;
    uint8_t *pin = plaintext.bytes;
    uint8_t *pout = ciphertext.bytes;
    aes_state_t pt;
    aes_state_t ct;
    AES aes = AES(key);
    uint32_t blocks = plaintext.length / AES_BLOCK_SIZE_BYTES;
    for (int i = 0; i < blocks; i++)
    {
        memcpy(pt.bytes, pin, sizeof(pt.bytes));
        aes.encrypt(ct, pt);
        memcpy(pout, ct.bytes, sizeof(ct.bytes));

        pin += AES_BLOCK_SIZE_BYTES;
        pout += AES_BLOCK_SIZE_BYTES;
        written += AES_BLOCK_SIZE_BYTES;
    }

    return written;
}

int32_t AESECB::decrypt(buffer_t &plaintext, const buffer_t &ciphertext, const aes_key_t &key)
{
    if ((plaintext.bytes == NULL) || (ciphertext.bytes == NULL))
    {
        return 0;
    }
    else if ((plaintext.length != ciphertext.length) || (ciphertext.length % AES_BLOCK_SIZE_BYTES))
    {
        return -1;
    }

    int32_t written = 0;
    uint8_t *pin = ciphertext.bytes;
    uint8_t *pout = plaintext.bytes;
    aes_state_t pt;
    aes_state_t ct;
    AES aes = AES(key);
    uint32_t blocks = plaintext.length / AES_BLOCK_SIZE_BYTES;
    for (int i = 0; i < blocks; i++)
    {
        memcpy(ct.bytes, pin, sizeof(ct.bytes));
        aes.decrypt(pt, ct);
        memcpy(pout, pt.bytes, sizeof(pt.bytes));

        pin += AES_BLOCK_SIZE_BYTES;
        pout += AES_BLOCK_SIZE_BYTES;
        written += AES_BLOCK_SIZE_BYTES;
    }

    return written;
}
