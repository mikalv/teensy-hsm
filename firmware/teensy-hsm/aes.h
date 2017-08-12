#ifndef __AES_H__
#define __AES_H__

#include <stdint.h>
#include "sizes.h"

//------------------------------------------------------------------------------
// Data Structure
//------------------------------------------------------------------------------
typedef union
{
  uint8_t bytes[THSM_BLOCK_SIZE];
  uint32_t words[THSM_BLOCK_SIZE / sizeof(uint32_t)];
} aes_state_t;

typedef struct {
  aes_state_t keys[15];
} aes_subkeys_t;

class AES {
  public:
    AES();
    void init   (uint8_t *key, uint16_t key_length);
    void encrypt(aes_state_t &ciphertext, aes_state_t &plaintext);
    void decrypt(aes_state_t &plaintext,  aes_state_t &ciphertext);
  private:
    aes_subkeys_t subkeys;
};

#endif
