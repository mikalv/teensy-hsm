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

//======================================================================================================================
// CLASSES
//======================================================================================================================
class AES
{
public:
	AES();
	~AES();
	void init(const aes_state_t &key);
	void init(const uint8_t *key);
	void encrypt(aes_state_t &ciphertext, const aes_state_t &plaintext);
	void encrypt(uint8_t *ciphertext, const uint8_t *plaintext);
	void decrypt(aes_state_t &plaintext, const aes_state_t &ciphertext);
	void decrypt(uint8_t *plaintext, const uint8_t *ciphertext);
	void clear();
	static void state_copy(aes_state_t &dst, const aes_state_t &src);
	static uint8_t *state_copy(aes_state_t &dst, const uint8_t *src);
	static uint8_t *state_copy(aes_state_t &dst, const uint8_t *src, uint32_t length);
	static uint8_t *state_copy(uint8_t *dst, const aes_state_t &src);
	static uint8_t *state_copy(uint8_t *dst, const aes_state_t &src, uint32_t length);
	static void state_xor(aes_state_t &dst, const aes_state_t &src1, const aes_state_t &src2);
	static bool state_compare(const aes_state_t &s1, const aes_state_t &s2);
	static bool state_compare(const aes_state_t &s1, const uint8_t *s2);
	static void state_truncate(aes_state_t &state, uint32_t length);
	static void state_increment(aes_state_t &state);
#ifdef DEBUG_AES
	static void state_dump(const char *title, const aes_state_t &state);
#endif
private:
	void encrypt_step(aes_state_t &dst, const aes_state_t &src, const aes_state_t &key);
	void encrypt_final(aes_state_t &dst, const aes_state_t &src, const aes_state_t &key);
	void decrypt_step(aes_state_t &dst, const aes_state_t &src, const aes_state_t &key);
	void decrypt_final(aes_state_t &dst, const aes_state_t &src, const aes_state_t &key);

	aes_state_t subkeys[11];
};

#endif
