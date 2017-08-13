#ifndef __AES_H__
#define __AES_H__

#include <stdint.h>

//======================================================================================================================
// MACROS
//======================================================================================================================
#define AES_BLOCK_SIZE_BITS     128
#define AES_BLOCK_SIZE_BYTES    (AES_BLOCK_SIZE_BITS/8)
#define AES_BLOCK_SIZE_WORDS    (AES_BLOCK_SIZE_BYTES / sizeof(uint32_t))
#define AES_KEY_SIZE_BITS       128
#define AES_KEY_SIZE_BYTES      (AES_KEY_SIZE_BITS/8)

//======================================================================================================================
// STRUCTURES
//======================================================================================================================
typedef union
{
    uint8_t bytes[AES_BLOCK_SIZE_BYTES];
    uint32_t words[AES_BLOCK_SIZE_WORDS];
} aes_state_t;

typedef struct
{
    uint8_t bytes[AES_KEY_SIZE_BYTES];
} aes_key_t;

//======================================================================================================================
// CLASSES
//======================================================================================================================
class AES
{
public:
    AES(const aes_key_t &key);
    ~AES();
    void encrypt(aes_state_t &ciphertext, const aes_state_t &plaintext);
    void decrypt(aes_state_t &plaintext, const aes_state_t &ciphertext);
private:
    void init(const aes_key_t &key);
    void encrypt_step(aes_state_t &dst, const aes_state_t &src, const aes_state_t &key);
    void encrypt_final(aes_state_t &dst, const aes_state_t &src, const aes_state_t &key);
    void decrypt_step(aes_state_t &dst, const aes_state_t &src, const aes_state_t &key);
    void decrypt_final(aes_state_t &dst, const aes_state_t &src, const aes_state_t &key);
    void state_xor(aes_state_t &dst, const aes_state_t &src1, const aes_state_t &src2);

    aes_state_t subkeys[11];
    aes_state_t ctx;
};

#endif
