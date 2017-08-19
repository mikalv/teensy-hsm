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
    clear();
}

void AESCCM::init(const aes_state_t &key, const uint32_t key_handle, const aes_ccm_nonce_t &nonce, uint16_t length)
{
    this->counter = 0;
    this->key_handle = key_handle;
    this->length = length;
    this->remaining = length;
    AESCCM::nonce_copy(this->nonce, nonce);

    ctx.init(key);
    reset();
}

void AESCCM::encrypt_update(aes_state_t &ciphertext, const aes_state_t &plaintext)
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

void AESCCM::encrypt(uint8_t *p_ciphertext, const uint8_t *p_plaintext, uint32_t plaintext_length, uint32_t key_handle, const uint8_t *p_key,
        const uint8_t *p_nonce)
{
    aes_ccm_nonce_t nonce;
    aes_ccm_mac_t mac;
    aes_state_t key, pt, ct;

    AESCCM::nonce_copy(nonce, p_nonce);
    AES::state_copy(key, p_key);
    init(key, key_handle, nonce, plaintext_length);

    while (plaintext_length)
    {
        uint32_t step = MIN(plaintext_length, sizeof(pt.bytes));
        p_plaintext = AES::state_copy(pt, p_plaintext, step);
        encrypt_update(ct, pt);
        p_ciphertext = AES::state_copy(p_ciphertext, ct, step);

        plaintext_length -= step;
    }

    encrypt_final(mac);
    AESCCM::mac_copy(p_ciphertext, mac);

    reset();
}

/**
 * Perform one-shot AES-CCM decryption
 * @param[in] p_plaintext
 */
bool AESCCM::decrypt(uint8_t *p_plaintext, const uint8_t *p_ciphertext, uint32_t ciphertext_length, uint32_t key_handle, const uint8_t *p_key,
        const uint8_t *p_nonce)
{
    aes_ccm_nonce_t nonce;
    aes_ccm_mac_t mac;
    aes_state_t key, pt, ct;

    /* cipher-text length must be at least (AES_CCM_MAC_SIZE_BYTES + 1) */
    if (ciphertext_length <= AES_CCM_MAC_SIZE_BYTES)
    {
        return false;
    }

    uint32_t length = ciphertext_length - AES_CCM_MAC_SIZE_BYTES;
    AESCCM::nonce_copy(nonce, p_nonce);
    AESCCM::mac_copy(mac, p_ciphertext + length);
    AES::state_copy(key, p_key);
    init(key, key_handle, nonce, length);

    while (length)
    {
        uint32_t step = MIN(length, sizeof(ct.bytes));
        p_ciphertext = AES::state_copy(ct, p_ciphertext, step);
        decrypt_update(pt, ct);
        p_plaintext = AES::state_copy(p_plaintext, pt, step);

        length -= step;
    }

    /* compare MAC */
    bool match = decrypt_final(mac);
    reset();

    return match;
}

uint8_t *AESCCM::nonce_copy(aes_ccm_nonce_t &dst, const uint8_t *src)
{
    memcpy(dst.bytes, src, sizeof(dst.bytes));
    return (uint8_t *) (src + sizeof(dst.bytes));
}

void AESCCM::nonce_copy(aes_ccm_nonce_t &dst, const aes_ccm_nonce_t &src)
{
    memcpy(dst.bytes, src.bytes, sizeof(src.bytes));
}

uint8_t * AESCCM::nonce_copy(uint8_t *dst, const aes_ccm_nonce_t &src)
{
    memcpy(dst, src.bytes, sizeof(src.bytes));
    return (uint8_t *) (dst + sizeof(src.bytes));
}

uint8_t * AESCCM::mac_copy(aes_ccm_mac_t &dst, const uint8_t *src)
{
    memcpy(dst.bytes, src, sizeof(dst.bytes));
    return (uint8_t *) (src + sizeof(dst.bytes));
}

uint8_t * AESCCM::mac_copy(uint8_t *dst, const aes_ccm_mac_t &src)
{
    memcpy(dst, src.bytes, sizeof(src.bytes));
    return (uint8_t *) (dst + sizeof(src.bytes));
}

bool AESCCM::mac_compare(const aes_ccm_mac_t &v1, const uint8_t *v2)
{
    return memcmp(v1.bytes, v2, sizeof(v1.bytes)) == 0;
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
