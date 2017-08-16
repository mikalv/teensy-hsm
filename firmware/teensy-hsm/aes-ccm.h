#ifndef __AES_CCM_H__
#define __AES_CCM_H__

#include "aes.h"
#include "buffer.h"

#define AES_CCM_KEY_HANDLE_SIZE_BYTES   sizeof(uint32_t)
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

class Counter
{
public:
	Counter();
	~Counter();
	void init(uint32_t key_handle, const aes_ccm_nonce_t &nonce);
	void encode(aes_state_t &out);
	void reset();
	void clear();
private:
	uint8_t flags;
	uint16_t counter;
	uint32_t key_handle;
	aes_ccm_nonce_t nonce;
};

class Iv
{
public:
	Iv();
	~Iv();
	void init(uint32_t key_handle, const aes_ccm_nonce_t &nonce, uint16_t length);
	void encode(aes_state_t &out);
	void reset();
	void clear();
private:
	uint8_t flags;
	uint16_t length;
	uint32_t key_handle;
	aes_ccm_nonce_t nonce;
};

class AESCCM
{
public:
	AESCCM();
	~AESCCM();
	void init(const aes_state_t &key, const uint32_t key_handle, const aes_ccm_nonce_t &nonce, uint16_t message_length);
	void encrypt_update(aes_state_t &ciphertext, const aes_state_t &plaintext);
	void encrypt_final(aes_state_t &ciphertext, aes_ccm_mac_t &mac, const aes_state_t &plaintext);
	void decrypt_update(aes_state_t &plaintext, const aes_state_t &ciphertext);
	bool decrypt_final(aes_state_t &plaintext, const aes_ccm_mac_t &mac, const aes_state_t &ciphertext);
	void reset();
	void clear();
private:
	void generate_token(aes_state_t &token);
	void generate_iv(aes_state_t &out);
	AES ctx;
	aes_state_t tmp_mac;
	uint16_t length;
	uint16_t counter;
	uint32_t key_handle;
	aes_ccm_nonce_t nonce;
};

#endif
