//==================================================================================================
// Project : Teensy HSM
// Author  : Edi Permadi
// Repo    : https://github.com/edipermadi/teensy-hsm
//
// This file is part of TeensyHSM project containing the implementation of persistent storage
// (EEPROM) related functionality.
//==================================================================================================
#define STORAGE_DEBUG

#include "error.h"
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

int32_t Storage::load(const aes_state_t &key, const aes_state_t &iv)
{
	/* load EEPROM */
	eeprom_buffer_t eeprom;
	load_from_eeprom(eeprom);

	/* setup pointers */
	uint8_t *ptr_in = &eeprom.layout.storage.body;
	uint8_t *ptr_out = &storage;
	uint32_t length = sizeof(storage);

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
	SHA1HMAC hmac = SHA1HMAC();
	hmac.init(key.bytes, sizeof(key.bytes));
	bool validated = hmac.compare(eeprom.layout.storage.mac, (uint8_t *) &storage, sizeof(storage));
	if (!validated)
	{
		clear();
		return ERROR_CODE_STORAGE_ENCRYPTED;
	}

	storage_decrypted = true;
	return ERROR_CODE_NONE;
}

int32_t Storage::store(const aes_state_t &key, const aes_state_t &iv)
{
	/* ignore if storage not deciphered yet */
	if (!storage_decrypted)
	{
		return ERROR_CODE_STORAGE_ENCRYPTED;
	}

	eeprom_buffer_t eeprom, current;
	MEMCLR(eeprom);
	MEMCLR(current);

	/* load current EEPROM */
	load_from_eeprom(current);

	/* copy plain values */
	eeprom.layout.restart_counter = current.layout.restart_counter;
	eeprom.layout.storage.store_counter = (current.layout.storage.store_counter + 1);
	memcpy(eeprom.layout.prng_seed, current.layout.prng_seed, sizeof(current.layout.prng_seed));

	/* calculate MAC */
	SHA1HMAC hmac = SHA1HMAC();
	hmac.init(key.bytes, sizeof(key.bytes));
	hmac.calculate(eeprom.layout.storage.mac, (uint8_t *) &storage, sizeof(storage));

	/* encrypt storage */
	uint8_t *ptr_in = &storage;
	uint8_t *ptr_out = &eeprom.layout.storage.body;
	uint32_t length = sizeof(storage);

	/* setup AES */
	aes_state_t pt, ct;
	AESCBC aes = AESCBC();
	aes.init(key, iv);

	/* encipher storage */
	while (length)
	{
		MEMCLR(pt);
		uint32_t step = MIN(length, AES_BLOCK_SIZE_BYTES);
		AES::state_fill(pt, ptr_in);
		aes.encrypt(ct, pt);
		memcpy(ptr_out, ct.bytes, step);

		ptr_in += step;
		ptr_out += step;
		length -= step;
	}

	return ERROR_CODE_NONE;
}

int32_t Storage::load_key(key_info_t &key, uint32_t key_handle)
{
	for (int i = 0; i < STORAGE_KEY_ENTRIES; i++)
	{
		if(storage.keys[i].key_handle == key_handle){
			key.handle = key_handle;
			key.flags = storage.keys[i].key_flags;
		}
	}

	return ERROR_CODE_KEY_NOT_FOUND;
}

int32_t Storage::store_key(uint32_t slot, const key_info_t &key)
{
}

int32_t Storage::load_secret(secret_info_t &secret, uint32_t key_handle, const aes_ccm_nonce_t &nonce)
{
}

int32_t Storage::store_secret(uint32_t slot, const secret_info_t & secret, uint32_t key_handle, const aes_ccm_nonce_t &nonce)
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
