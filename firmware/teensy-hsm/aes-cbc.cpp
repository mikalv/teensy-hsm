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
    uint8_t *pin = plaintext.bytes;
    uint8_t *pout = ciphertext.bytes;
    aes_state_t pt, ct;
    AES aes = AES(key);

    state_copy(ct, iv);
    uint32_t blocks = plaintext.length / AES_BLOCK_SIZE_BYTES;
    for (uint32_t i = 0; i < blocks; i++)
    {
        memcpy(pt.bytes, pin, sizeof(pt.bytes));
        state_xor(pt, pt, ct);
        aes.encrypt(ct, pt);
        memcpy(pout, ct.bytes, sizeof(ct.bytes));

        pin += AES_BLOCK_SIZE_BYTES;
        pout += AES_BLOCK_SIZE_BYTES;
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
    uint8_t *pin = ciphertext.bytes;
    uint8_t *pout = plaintext.bytes;
    aes_state_t pt, ct, tmp;
    AES aes = AES(key);

    state_copy(tmp, iv);
    uint32_t blocks = plaintext.length / AES_BLOCK_SIZE_BYTES;
    for (uint32_t i = 0; i < blocks; i++)
    {
        memcpy(ct.bytes, pin, sizeof(ct.bytes));
        aes.decrypt(pt, ct);
        state_xor(pt, pt, tmp);
        memcpy(pout, pt.bytes, sizeof(pt.bytes));
        state_copy(tmp, ct);

        pin += AES_BLOCK_SIZE_BYTES;
        pout += AES_BLOCK_SIZE_BYTES;
        written += AES_BLOCK_SIZE_BYTES;
    }

    return written;
}

void AESCBC::state_xor(aes_state_t &dst, const aes_state_t &src1, const aes_state_t &src2)
{
    const uint32_t *sw1 = src1.words;
    const uint32_t *sw2 = src2.words;
    uint32_t *dw = dst.words;

    dw[0] = sw1[0] ^ sw2[0];
    dw[1] = sw1[1] ^ sw2[1];
    dw[2] = sw1[2] ^ sw2[2];
    dw[3] = sw1[3] ^ sw2[3];
}

void AESCBC::state_copy(aes_state_t &dst, const aes_state_t &src)
{
    const uint32_t *sw = src.words;
    uint32_t *dw = dst.words;

    dw[0] = sw[0];
    dw[1] = sw[1];
    dw[2] = sw[2];
    dw[3] = sw[3];
}
