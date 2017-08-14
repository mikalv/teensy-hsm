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

Counter::Counter(uint32_t key_handle, const ccm_nonce_t &nonce)
{
    this->flags = 0x19;
    this->counter = 1;
    this->key_handle = key_handle;
    memcpy(this->nonce.bytes, nonce.bytes, sizeof(this->nonce.bytes));
}

void Counter::encode(aes_state_t &out)
{
    memset(out.bytes, 0, sizeof(out.bytes));
    uint8_t *ptr = out.bytes;

    *ptr++ = flags;
    WRITE32(ptr, key_handle);
    memcpy(ptr, nonce.bytes, sizeof(nonce.bytes));
    uint16_t value = counter++;
    out.bytes[14] = (uint8_t) (value >> 8);
    out.bytes[15] = (uint8_t) (value >> 0);
}

Iv::Iv(uint32_t key_handle, const ccm_nonce_t &nonce, uint16_t length)
{
    this->flags = 0x01;
    this->length = length;
    this->key_handle = key_handle;
    memcpy(this->nonce.bytes, nonce.bytes, sizeof(this->nonce.bytes));
}

void Iv::encode(aes_state_t &out)
{
    memset(out.bytes, 0, sizeof(out.bytes));
    uint8_t *ptr = out.bytes;

    *ptr++ = flags;
    WRITE32(ptr, key_handle);
    memcpy(ptr, nonce.bytes, sizeof(nonce.bytes));
    out.bytes[14] = (uint8_t) (length >> 8);
    out.bytes[15] = (uint8_t) (length >> 0);
}

int32_t AESCCM::encrypt(buffer_t &ciphertext, const buffer_t &plaintext, const aes_state_t &key,
        const uint32_t key_handle, const ccm_nonce_t &nonce)
{
    if (!plaintext.length || !plaintext.bytes)
    {
        return 0;
    }
    else if (plaintext.length >= MAX_LENGTH)
    {
        return -1;
    }
    else if (!ciphertext.bytes || (ciphertext.length < (plaintext.length + AES_CCM_MAC_SIZE_BYTES)))
    {
        return -2;
    }

    uint8_t *p_in = plaintext.bytes;
    uint8_t *p_out = ciphertext.bytes;
    aes_state_t mac_in, mac_out, ctr_in, ctr_out, pt, ct;

    AES aes = AES(key);
    Counter ctr = Counter(key_handle, nonce);
    Iv iv = Iv(key_handle, nonce, plaintext.length);

    /* setup MAC */
    iv.encode(mac_in);
    aes.encrypt(mac_out, mac_in);

    uint32_t written = 0;
    uint32_t length = plaintext.length;
    while (length)
    {
        MEMCLR(pt);
        uint32_t step = MIN(length, AES_BLOCK_SIZE_BYTES);

        /* run AES-CTR */
        ctr.encode(ctr_in);
        aes.encrypt(ctr_out, ctr_in);

        /* XOR plain-text with ctr_out */
        memcpy(pt.bytes, p_in, step);
        AES::state_xor(ct, pt, ctr_out);
        memcpy(p_out, ct.bytes, step);

        /* update MAC */
        AES::state_xor(mac_in, pt, mac_out);
        aes.encrypt(mac_out, mac_in);

        length -= step;
        written += step;
        p_in += step;
        p_out += step;
    }

    /* append MAC */
    memcpy(p_out, mac_out.bytes, AES_CCM_MAC_SIZE_BYTES);
    written += AES_CCM_MAC_SIZE_BYTES;

    return written;
}

int32_t AESCCM::decrypt(buffer_t &plaintext, const buffer_t &ciphertext, const aes_state_t &key,
        const uint32_t key_handle, const ccm_nonce_t &nonce)
{
    if ((ciphertext.length <= AES_CCM_MAC_SIZE_BYTES) || !ciphertext.bytes)
    {
        return 0;
    }
    else if (plaintext.length < (ciphertext.length - AES_CCM_MAC_SIZE_BYTES))
    {
        return -1;
    }

    uint8_t *pin = ciphertext.bytes;
    uint8_t *pout = plaintext.bytes;
    aes_state_t mac_in, mac_out, ctr_in, ctr_out, pt, ct;

    AES aes = AES(key);
    Counter ctr = Counter(key_handle, nonce);
    Iv iv = Iv(key_handle, nonce, plaintext.length);

    /* setup MAC */
    iv.encode(mac_in);
    aes.encrypt(mac_out, mac_in);

    uint32_t written = 0;
    uint32_t length = ciphertext.length - AES_CCM_MAC_SIZE_BYTES;
    while (length)
    {
        MEMCLR(ct);
        uint32_t step = MIN(length, AES_BLOCK_SIZE_BYTES);

        /* run AES-CTR */
        ctr.encode(ctr_in);
        aes.encrypt(ctr_out, ctr_in);

        /* XOR plain-text with ctr_out */
        memcpy(ct.bytes, pin, step);
        AES::state_xor(pt, ct, ctr_out);
        memcpy(pout, pt.bytes, step);

        /* update MAC */
        AES::state_xor(mac_in, pt, mac_out);
        aes.encrypt(mac_out, mac_in);

        length -= step;
        written += step;
        pin += step;
        pout += step;
    }

    // compare MAC
    if (memcmp(mac_out.bytes, pin, AES_CCM_MAC_SIZE_BYTES) != 0)
    {
        return -2;
    }

    return written;
}

