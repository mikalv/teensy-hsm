#ifndef __FLAGS_H__
#define __FLAGS_H__

//------------------------------------------------------------------------------
// Imports
//------------------------------------------------------------------------------
#include <stdint.h>


//------------------------------------------------------------------------------
// Function Prototypes
//------------------------------------------------------------------------------
void flags_set_secret_locked(uint8_t value);
void flags_set_storage_encrypted(uint8_t value);
uint8_t flags_is_secret_locked();
uint8_t flags_is_storage_decrypted();

#endif
