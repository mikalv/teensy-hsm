//==================================================================================================
// Project : Teensy HSM
// Author  : Edi Permadi
// Repo    : https://github.com/edipermadi/teensy-hsm
//
// This file is part of TeensyHSM project containing the implementation of persistent storage
// (EEPROM) related functionality.
//==================================================================================================
#define STORAGE_DEBUG

#include "storage.h"
#include "aes-cbc.h"
#include "sha1-hmac.h"

#ifndef STORAGE_DEBUG
#include <EEPROM.h>
#define NV_WRITE(i,v)   EEPROM.write((i), (v))
#define NV_READ(i)      EEPROM.read((i))
#else
uint8_t nv_storage[EEPROM_SIZE_BYTES];
#define NV_WRITE(i,v)   nv_storage[(i) & EEPROM_SIZE_BYTES] = (v)
#define NV_READ(i)      nv_storage[(i) & EEPROM_SIZE_BYTES]
#endif

Storage::Storage()
{
	storage_decrypted = false;
	secret_unlocked = false;
}

bool Storage::load(const aes_state_t &key, const aes_state_t &iv)
{
	/* load eeprom */
	eeprom_buffer_t eeprom;
	load_from_eeprom(eeprom);

	/* setup hmac */
	uint32_t hmac_key_buffer[AES_BLOCK_SIZE_BYTES * 2];
	buffer_t hmac_key = buffer_t(hmac_key_buffer, sizeof(hmac_key_buffer));
	memcpy(&hmac_key_buffer[0], key.bytes, sizeof(key.bytes));
	memcpy(&hmac_key_buffer[sizeof(key.bytes)], iv.bytes, sizeof(iv.bytes));
	SHA1HMAC hmac = SHA1HMAC();
	hmac.init(hmac_key);

	/* setup pointers */
	uint8_t *ptr_in = &eeprom.layout.storage.body;
	uint8_t *ptr_out = &storage.body;
	uint32_t length = sizeof(storage.body);

	/* setup AES */
	aes_state_t pt, ct;
	AESCBC aes = AESCBC();
	aes.init(key, iv);

	/* decipher storage */
	while (length)
	{
		MEMCLR(pt);
		uint32_t step = MIN(length, AES_BLOCK_SIZE_BYTES);
		AES::state_fill(ct, ptr_in);
		aes.decrypt(pt, ct);
		memcpy(ptr_out, pt.bytes, step);

		ptr_in += step;
		ptr_out += step;
		length -= step;
	}

	/* verify deciphered storage */
	buffer_t decrypted = buffer_t(&storage.body, sizeof(storage.body));
	bool validated = hmac.compare(decrypted, eeprom.layout.storage.mac);
	if (validated)
	{
		memcpy(storage.mac.bytes, eeprom.layout.storage.mac.bytes, sizeof(eeprom.layout.storage.mac.bytes));
		storage.store_counter = eeprom.layout.storage.store_counter;
		storage_decrypted = true;
	}
	else
	{
		clear();
	}

	return validated;
}

void Storage::store(const aes_state_t &key, const aes_state_t &iv)
{
	eeprom_buffer_t eeprom;

}

int32_t Storage::load_key(key_info_t &key, uint32_t handle)
{
}

int32_t Storage::store_key(uint32_t slot, const key_info_t &key)
{
}

int32_t Storage::load_secret(secret_info_t &secret, uint32_t key_handle, const ccm_nonce_t &nonce)
{
}

int32_t Storage::store_secret(uint32_t slot, const secret_info_t & secret, uint32_t key_handle, const ccm_nonce_t &nonce)
{
}

void Storage::clear()
{
	storage_decrypted = false;
	secret_unlocked = false;
	MEMCLR(storage);
}
void Storage::format()
{
}

void Storage::load_from_eeprom(eeprom_buffer_t &eeprom)
{
	MEMCLR(eeprom);
	for (int i = 0; i < sizeof(eeprom.bytes); i++)
	{
		eeprom.bytes[i] = NV_READ(i);
	}
}

void Storage::store_to_eeprom(const eeprom_buffer_t &eeprom)
{
	for (int i = 0; i < sizeof(eeprom.bytes); i++)
	{
		NV_WRITE(i, eeprom.bytes[i]);
	}
}
