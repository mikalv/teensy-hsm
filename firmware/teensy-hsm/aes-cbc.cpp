#include <string.h>
#include "macros.h"
#include "aes-cbc.h"

AESCBC::AESCBC(const aes_state_t &key, const aes_state_t &iv) {
    ctx.init(key);
    AES::state_copy(this->iv, iv);
    reset();
}

AESCBC::~AESCBC() {
    clear();
}

void AESCBC::encrypt(aes_state_t &ciphertext, const aes_state_t &plaintext) {
    aes_state_t tmp;

    AES::state_xor(tmp, tmp_enc, plaintext);
    ctx.encrypt(tmp_enc, tmp);
    AES::state_copy(ciphertext, tmp_enc);
}

void AESCBC::decrypt(aes_state_t &plaintext, const aes_state_t &ciphertext) {
    aes_state_t tmp;
    ctx.decrypt(tmp, ciphertext);
    AES::state_xor(plaintext, tmp_dec, tmp);
    AES::state_copy(tmp_dec, ciphertext);
}

void AESCBC::reset() {
    AES::state_copy(tmp_enc, iv);
    AES::state_copy(tmp_dec, iv);
}

void AESCBC::clear() {
    MEMCLR(iv);
    MEMCLR(tmp_enc);
    MEMCLR(tmp_dec);
    this->ctx.clear();
}
