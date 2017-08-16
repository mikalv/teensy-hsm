#include <string.h>
#include "aes-ccm.h"
#include "macros.h"

// Reference:
// https://tools.ietf.org/html/rfc3610

// MAC Flag
// 0 0 011 001
//   |  |   |
//   |  |   `---> 2 bytes of message length field
//   |  `-------> 8 bytes of MAC
//   `----------> no additional authenticated data

// CTR Flag
// 0 0 000 001
//          |
//          `---> 2 bytes of length field

#define MAX_LENGTH  (BUFFER_SIZE_BYTES - AES_CCM_MAC_SIZE_BYTES)

AESCCM::AESCCM()
{
    clear();
}

AESCCM::~AESCCM()
{

}

void AESCCM::init(const aes_state_t &key, const uint32_t key_handle, const aes_ccm_nonce_t &nonce, uint16_t length)
{
    this->counter = 0;
    this->key_handle = key_handle;
    this->length = length;
    this->remaining = length;
    memcpy(this->nonce.bytes, nonce.bytes, sizeof(nonce.bytes));

    ctx.init(key);
    reset();
}

void AESCCM::encrypt_update(aes_state_t &ciphertext, const aes_state_t &plaintext)
{
    aes_state_t token, tmp;
    uint32_t step = MIN(remaining, sizeof(tmp.bytes));

    /* encrypt */
    generate_token(tmp);
    ctx.encrypt(token, tmp);
    AES::state_xor(ciphertext, plaintext, token);

    /* update MAC */
    AES::state_xor(tmp, plaintext, tmp_mac);
    ctx.encrypt(tmp_mac, tmp);
    remaining -= step;
}

void AESCCM::encrypt_final(aes_ccm_mac_t &mac)
{
    memcpy(mac.bytes, tmp_mac.bytes, AES_CCM_MAC_SIZE_BYTES);
}

void AESCCM::decrypt_update(aes_state_t &plaintext, const aes_state_t &ciphertext)
{
    if (!remaining)
    {
        return;
    }

    aes_state_t token, tmp;
    uint32_t step = MIN(remaining, sizeof(tmp.bytes));

    /* encrypt */
    generate_token(tmp);
    ctx.encrypt(token, tmp);
    AES::state_xor(plaintext, ciphertext, token);
    AES::state_truncate(plaintext, step);

    /* update MAC */
    AES::state_xor(tmp, plaintext, tmp_mac);
    ctx.encrypt(tmp_mac, tmp);
    remaining -= step;
}

bool AESCCM::decrypt_final(const aes_ccm_mac_t &mac)
{
    return memcmp(tmp_mac.bytes, mac.bytes, sizeof(mac.bytes)) == 0;
}

void AESCCM::reset()
{
    aes_state_t tmp;

    remaining = length;
    counter = 0;
    generate_iv(tmp);
    ctx.encrypt(tmp_mac, tmp);
}

void AESCCM::clear()
{
    counter = 0;
    length = 0;
    remaining = 0;
    key_handle = 0;
    ctx.clear();
    MEMCLR(tmp_mac);
    MEMCLR(nonce);
}

void AESCCM::generate_token(aes_state_t &out)
{
    MEMCLR(out);
    uint8_t *ptr = out.bytes;

    *ptr++ = 0x19;
    WRITE32(ptr, key_handle);
    ptr += sizeof(uint32_t);
    memcpy(ptr, nonce.bytes, sizeof(nonce.bytes));
    uint16_t value = ++counter;
    out.bytes[14] = (uint8_t) (value >> 8);
    out.bytes[15] = (uint8_t) (value >> 0);
}

void AESCCM::generate_iv(aes_state_t &out)
{
    MEMCLR(out);
    uint8_t *ptr = out.bytes;

    *ptr++ = 0x01;
    WRITE32(ptr, key_handle);
    ptr += sizeof(uint32_t);
    memcpy(ptr, nonce.bytes, sizeof(nonce.bytes));
    out.bytes[14] = (uint8_t) (length >> 8);
    out.bytes[15] = (uint8_t) (length >> 0);
}
