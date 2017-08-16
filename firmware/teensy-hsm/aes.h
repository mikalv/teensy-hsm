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
	void encrypt(aes_state_t &ciphertext, const aes_state_t &plaintext);
	void decrypt(aes_state_t &plaintext, const aes_state_t &ciphertext);
	void clear();
	static void state_fill(aes_state_t &dst, uint8_t *data);
	static void state_xor(aes_state_t &dst, const aes_state_t &src1, const aes_state_t &src2);
	static void state_copy(aes_state_t &dst, const aes_state_t &src);
	static void state_truncate(aes_state_t &state, uint32_t length);
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
