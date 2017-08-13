#include <string.h>
#include "aes-ccm.h"

// Reference:
// https://tools.ietf.org/html/rfc3610

// MAC IV
// ----------------------
// | 0x19 | key_handle | nonce | counter


//--------------------------------------------------------------------------------------------------
// AES-CCM block cipher
//--------------------------------------------------------------------------------------------------
void aes128_ccm_encrypt(uint8_t *ct, uint8_t *mac, uint8_t *pt, uint16_t length, uint8_t *kh, uint8_t *cipherkey, uint8_t *nonce) {
  aes_subkeys_t sk;
  aes_state_t   tmp;
  aes_state_t   mac_in, mac_out;
  aes_state_t   cipher_in, cipher_out;

  /* set MAC IV */
  MEMSET(mac_in);
  mac_in.bytes[0] = 0x19; /* 8 bytes mac and 2 bytes counter */
  memcpy(&(mac_in.bytes[1]), kh,    THSM_KEY_HANDLE_SIZE);
  memcpy(&(mac_in.bytes[5]), nonce, THSM_AEAD_NONCE_SIZE);
  mac_in.bytes[15] = length;

  /* set cipher IV */
  memset(&cipher_in, 0, sizeof(cipher_in));
  cipher_in.bytes[0] = 0x01; /* 2 bytes counter */
  memcpy(&(cipher_in.bytes[1]), kh,    THSM_KEY_HANDLE_SIZE);
  memcpy(&(cipher_in.bytes[5]), nonce, THSM_AEAD_NONCE_SIZE);
  cipher_in.bytes[15] = 1;

  /* derive subkeys */
  aes_init(&sk, cipherkey, THSM_KEY_SIZE);

  /* perform encryption */
  while (length > 0) {
    /* load plaintext */
    uint8_t step = (length > THSM_BLOCK_SIZE) ? THSM_BLOCK_SIZE : length;
    memset(&tmp,       0, sizeof(tmp));
    memcpy(tmp.bytes, pt, step);

    /* perform encryption */
    aes_encrypt(&mac_out,    &mac_in,    &sk, THSM_KEY_SIZE);
    aes_encrypt(&cipher_out, &cipher_in, &sk, THSM_KEY_SIZE);

    /* xor mac stream with plaintext */
    aes_state_xor(&mac_in, &mac_out, &tmp);

    /* xor cipher stream with plaintext */
    aes_state_xor(&tmp, &tmp, &cipher_out);

    /* append to ciphertext */
    memcpy(ct, tmp.bytes, step);

    if (cipher_in.bytes[15] == 0xff) {
      cipher_in.bytes[15] = 0;
      cipher_in.bytes[14]++;
    } else {
      cipher_in.bytes[15]++;
    }

    /* update counter */
    length -= step;
    pt     += step;
    ct     += step;
  }

  aes_encrypt(&tmp, &mac_in, &sk, THSM_KEY_SIZE);

  /* set MAC iv */
  memset(&mac_in, 0, sizeof(mac_in));
  mac_in.bytes[0] = 0x19; /* 8 bytes mac and 2 bytes counter */
  memcpy(&(mac_in.bytes[1]), kh,    4);
  memcpy(&(mac_in.bytes[5]), nonce, THSM_AEAD_NONCE_SIZE);

  /* perform encryption */
  aes_encrypt(&mac_out, &mac_in, &sk, THSM_KEY_SIZE);
  aes_state_xor(&tmp, &tmp, &mac_out);


  if (mac == NULL) {
    /* append mac to ciphertext result */
    memcpy(ct,  tmp.bytes, THSM_AEAD_MAC_SIZE);
  } else {
    /* store mac */
    memcpy(mac, tmp.bytes, THSM_AEAD_MAC_SIZE);
  }

  /* cleanup temporary variables */
  memset(&sk,         0, sizeof(sk));
  memset(&tmp,        0, sizeof(tmp));
  memset(&mac_in,     0, sizeof(mac_in));
  memset(&mac_out,    0, sizeof(mac_out));
  memset(&cipher_in,  0, sizeof(cipher_in));
  memset(&cipher_out, 0, sizeof(cipher_out));
}

uint8_t aes128_ccm_decrypt(uint8_t *pt, uint8_t *ct, uint16_t length, uint8_t *kh, uint8_t *cipherkey, uint8_t *nonce, uint8_t *mac) {
  aes_subkeys_t sk;
  aes_state_t   tmp;
  aes_state_t   mac_in, mac_out;
  aes_state_t   cipher_in, cipher_out;

  /* set MAC IV */
  memset(&mac_in, 0, sizeof(mac_in));
  mac_in.bytes[0] = 0x19; /* 8 bytes mac and 2 bytes counter */
  memcpy(&(mac_in.bytes[1]), kh,    4);
  memcpy(&(mac_in.bytes[5]), nonce, THSM_AEAD_NONCE_SIZE);
  mac_in.bytes[15] = length;

  /* set cipher IV */
  memset(&cipher_in, 0, sizeof(cipher_in));
  cipher_in.bytes[0] = 0x01; /* 2 bytes counter */
  memcpy(&(cipher_in.bytes[1]), kh,    4);
  memcpy(&(cipher_in.bytes[5]), nonce, THSM_AEAD_NONCE_SIZE);
  cipher_in.bytes[15] = 1;

  /* derive subkeys */
  aes_init(&sk, cipherkey, THSM_KEY_SIZE);

  /* perform decryption */
  while (length > 0) {
    /* load ciphertext */
    uint8_t step = (length > THSM_BLOCK_SIZE) ? THSM_BLOCK_SIZE : length;
    memset(&tmp,       0, sizeof(tmp));
    memcpy(tmp.bytes, ct, step);

    /* perform encryption */
    aes_encrypt(&mac_out,    &mac_in,    &sk, THSM_KEY_SIZE);
    aes_encrypt(&cipher_out, &cipher_in, &sk, THSM_KEY_SIZE);

    /* decrypt and update mac */
    aes_state_xor(&tmp,    &tmp,     &cipher_out);
    aes_state_xor(&mac_in, &mac_out, &tmp);

    /* append to plaintext */
    memcpy(pt, tmp.bytes, step);

    if (cipher_in.bytes[15] == 0xff) {
      cipher_in.bytes[15] = 0;
      cipher_in.bytes[14]++;
    } else {
      cipher_in.bytes[15]++;
    }

    /* update counter */
    length -= step;
    pt     += step;
    ct     += step;
  }

  aes_encrypt(&tmp, &mac_in, &sk, THSM_KEY_SIZE);

  /* set MAC iv */
  memset(&mac_in, 0, sizeof(mac_in));
  mac_in.bytes[0] = 0x19; /* 8 bytes mac and 2 bytes counter */
  memcpy(&(mac_in.bytes[1]), kh,    4);
  memcpy(&(mac_in.bytes[5]), nonce, THSM_AEAD_NONCE_SIZE);

  /* perform encryption */
  aes_encrypt(&mac_out, &mac_in, &sk, THSM_KEY_SIZE);
  aes_state_xor(&tmp, &tmp, &mac_out);

  /* compare known mac vs recovered mac */
  uint8_t matched = !memcmp(&tmp.bytes, mac, THSM_AEAD_MAC_SIZE);

  /* cleanup temporary variables */
  memset(&sk,         0, sizeof(sk));
  memset(&tmp,        0, sizeof(tmp));
  memset(&mac_in,     0, sizeof(mac_in));
  memset(&mac_out,    0, sizeof(mac_out));
  memset(&cipher_in,  0, sizeof(cipher_in));
  memset(&cipher_out, 0, sizeof(cipher_out));

  return matched;
}

