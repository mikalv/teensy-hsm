#include <string.h>
#include "macros.h"
#include "aes-cbc.h"

AESCBC::AESCBC()
{
}

AESCBC::~AESCBC()
{
    clear();
}

void AESCBC::init(const aes_state_t &key, const aes_state_t &iv)
{
    ctx.init(key);
    AES::state_copy(this->iv, iv);
    reset();
}

void AESCBC::encrypt(aes_state_t &ciphertext, const aes_state_t &plaintext)
{
    aes_state_t tmp;

    AES::state_xor(tmp, tmp_enc, plaintext);
    ctx.encrypt(tmp_enc, tmp);
    AES::state_copy(ciphertext, tmp_enc);
}

void AESCBC::encrypt(uint8_t *p_ciphertext, const uint8_t *p_plaintext, uint32_t plaintext_length, const uint8_t *p_key, const uint8_t *p_iv)
{
    aes_state_t key, iv, pt, ct;

    AES::state_copy(key, p_key);
    AES::state_copy(iv, p_iv);

    init(key, iv);
    while (plaintext_length)
    {
        uint32_t step = MIN(plaintext_length, sizeof(pt.bytes));
        p_plaintext = AES::state_copy(pt, p_plaintext, step);
        encrypt(ct, pt);
        p_ciphertext = AES::state_copy(p_ciphertext, ct, step);
        plaintext_length -= step;
    }

    clear();
}

void AESCBC::decrypt(aes_state_t &plaintext, const aes_state_t &ciphertext)
{
    aes_state_t tmp;
    ctx.decrypt(tmp, ciphertext);
    AES::state_xor(plaintext, tmp_dec, tmp);
    AES::state_copy(tmp_dec, ciphertext);
}

void AESCBC::decrypt(uint8_t *p_plaintext, const uint8_t *p_ciphertext, uint32_t ciphertext_length, const uint8_t *p_key, const uint8_t *p_iv)
{
    aes_state_t key, iv, pt, ct;

    AES::state_copy(key, p_key);
    AES::state_copy(iv, p_iv);

    init(key, iv);
    while (ciphertext_length)
    {
        uint32_t step = MIN(ciphertext_length, sizeof(ct.bytes));
        p_ciphertext = AES::state_copy(ct, p_ciphertext, step);
        decrypt(pt, ct);
        p_plaintext = AES::state_copy(p_plaintext, pt, step);
        ciphertext_length -= step;
    }

    clear();
}

void AESCBC::reset()
{
    AES::state_copy(tmp_enc, iv);
    AES::state_copy(tmp_dec, iv);
}

void AESCBC::clear()
{
    MEMCLR(iv);
    MEMCLR(tmp_enc);
    MEMCLR(tmp_dec);
    this->ctx.clear();
}
