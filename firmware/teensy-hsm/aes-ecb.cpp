

//--------------------------------------------------------------------------------------------------
// AES-ECB block cipher
//--------------------------------------------------------------------------------------------------
/**
   Perform AES-ECB encryption

   @param ciphertext  THSM_BLOCK_SIZE bytes of ciphertext buffer
   @param plaintext   THSM_BLOCK_SIZE bytes of plaintext buffer
   @param cipherkey   cipher-key buffer
   @param key_length  length of cipher-key buffer
*/
void aes_ecb_encrypt(uint8_t *ciphertext, uint8_t *plaintext, uint8_t *cipherkey, uint16_t key_length) {
  aes_subkeys_t sk;
  aes_state_t   ct, pt;

  /* derive sub-keys */
  aes_init(&sk, cipherkey, key_length);

  /* encrypt */
  memcpy(pt.bytes, plaintext, THSM_BLOCK_SIZE);
  aes_encrypt(&ct, &pt, &sk, key_length);
  memcpy(ciphertext, ct.bytes, THSM_BLOCK_SIZE);

  /* cleanup temporary variables */
  memset(&pt, 0, sizeof(pt));
  memset(&ct, 0, sizeof(ct));
  memset(&sk, 0, sizeof(sk));
}

/**
   Performs AES-ECB decryption

   @param plaintext   THSM_BLOCK_SIZE bytes of plaintext buffer
   @param ciphertext  THSM_BLOCK_SIZE bytes of ciphertext buffer
   @param cipherkey   cipher-key buffer
   @param key_length  length of cipher-key buffer
*/
void aes_ecb_decrypt(uint8_t *plaintext, uint8_t *ciphertext, uint8_t *cipherkey, uint16_t key_length) {
  aes_subkeys_t sk;
  aes_state_t   ct, pt;

  /* derive sub-keys */
  aes_init(&sk, cipherkey, key_length);

  /* decrypt */
  memcpy(ct.bytes, ciphertext, THSM_BLOCK_SIZE);
  aes_decrypt(&pt, &ct, &sk, key_length);
  memcpy(plaintext, pt.bytes, THSM_BLOCK_SIZE);

  /* cleanup temporary variables */
  memset(&pt, 0, sizeof(pt));
  memset(&ct, 0, sizeof(ct));
  memset(&sk, 0, sizeof(sk));
}
