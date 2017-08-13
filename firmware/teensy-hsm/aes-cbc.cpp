#include <string.h>
#include "aes-cbc.h"

AESCBC::AESCBC()
{
}
int32_t AESCBC::encrypt(buffer_t &ciphertext, const buffer_t &plaintext, const aes_key_t &key, const aes_key_t &iv)
{
}
int32_t AESCBC::decrypt(buffer_t &plaintext, const buffer_t &ciphertext, const aes_key_t &key, const aes_key_t &iv)
{
}

//--------------------------------------------------------------------------------------------------
// AES-CBC block cipher
//--------------------------------------------------------------------------------------------------
void aes_cbc_encrypt(uint8_t *ciphertext, uint8_t *plaintext, uint16_t length, uint8_t *cipherkey, uint16_t key_length)
{
    aes_subkeys_t sk;
    aes_state_t ct, pt;

    /* derive sub-keys and clear iv */
    memset(&ct, 0, sizeof(ct));
    aes_init(&sk, cipherkey, key_length);

    while (length > 0)
    {
        uint8_t step = (length > THSM_BLOCK_SIZE) ? THSM_BLOCK_SIZE : step;

        /* load plaintext */
        memset(&pt, 0, sizeof(pt));
        memcpy(pt.bytes, plaintext, step);

        /* xor plaintext */
        aes_state_xor(&pt, &pt, &ct);

        /* encrypt */
        aes_encrypt(&ct, &pt, &sk, key_length);

        /* copy to output */
        memcpy(ciphertext, ct.bytes, step);

        /* update pointers */
        plaintext += step;
        ciphertext += step;
        length -= step;
    }
}

void aes_cbc_decrypt(uint8_t *plaintext, uint8_t *ciphertext, uint16_t length, uint8_t *cipherkey, uint16_t key_length)
{
    aes_subkeys_t sk;
    aes_state_t ct, pt, iv;

    /* derive sub-keys and clear iv */
    memset(&iv, 0, sizeof(iv));
    aes_init(&sk, cipherkey, key_length);

    while (length > 0)
    {
        uint8_t step = (length > THSM_BLOCK_SIZE) ? THSM_BLOCK_SIZE : step;

        /* load ciphertext */
        memset(&ct, 0, sizeof(ct));
        memcpy(ct.bytes, ciphertext, step);

        /* decrypt */
        aes_decrypt(&pt, &ct, &sk, key_length);

        /* xor plaintext, update iv */
        aes_state_xor(&pt, &pt, &iv);
        memcpy(&iv, &ct, sizeof(ct));

        /* copy to plaintext */
        memcpy(plaintext, pt.bytes, step);

        length -= step;
        ciphertext += step;
        plaintext += step;
    }
}
