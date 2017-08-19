#ifndef __AES_CCM_H__
#define __AES_CCM_H__

#include "aes.h"
#include "buffer.h"

#define AES_CCM_MAC_SIZE_BITS           64
#define AES_CCM_MAC_SIZE_BYTES          (AES_CCM_MAC_SIZE_BITS / 8)
#define AES_CCM_MAC_SIZE_WORDS          (AES_CCM_MAC_SIZE_BYTES / sizeof(uint32_t))
#define AES_CCM_NONCE_SIZE_BITS         48
#define AES_CCM_NONCE_SIZE_BYTES        (AES_CCM_NONCE_SIZE_BITS / 8)
#define AES_CCM_NONCE_SIZE_WORDS        (AES_CCM_NONCE_SIZE_BYTES / sizeof(uint32_t))
#define AES_CCM_MAX_DATA_LENGTH_BYTES     64
#define AES_CCM_MAX_AEAD_LENGTH_BYTES   (AES_CCM_MAX_DATA_LENGTH_BYTES + AES_CCM_MAC_SIZE_BYTES)

typedef struct
{
	uint8_t bytes[AES_CCM_NONCE_SIZE_BYTES];
} aes_ccm_nonce_t;

typedef struct
{
	uint8_t bytes[AES_CCM_MAC_SIZE_BYTES];
} aes_ccm_mac_t;

class AESCCM
{
public:
	AESCCM();
	~AESCCM();
	void init(const aes_state_t &key, const uint32_t key_handle, const aes_ccm_nonce_t &nonce, uint16_t message_length);
	void encrypt_update(aes_state_t &ciphertext, const aes_state_t &plaintext);
	void encrypt_final(aes_ccm_mac_t &mac);
	void decrypt_update(aes_state_t &plaintext, const aes_state_t &ciphertext);
	bool decrypt_final(const aes_ccm_mac_t &mac);
	void encrypt(uint8_t *p_ciphertext, const uint8_t *p_plaintext, uint32_t plaintext_length, uint32_t key_handle, const uint8_t *p_key, const uint8_t *p_nonce);
	bool decrypt(uint8_t *p_plaintext, const uint8_t *p_ciphertext, uint32_t ciphertext_length, uint32_t key_handle, const uint8_t *p_key, const uint8_t *p_nonce);
	void reset();
	void clear();
private:
	void generate_token(aes_state_t &token);
	void generate_iv(aes_state_t &out);
	AES ctx;
	aes_state_t tmp_mac;
	uint16_t length, counter, remaining;
	uint32_t key_handle;
	aes_ccm_nonce_t nonce;
};

#endif
