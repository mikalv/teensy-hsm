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

class Flags
{
public:
    Flags();
    bool is_secret_unlocked();
    bool is_storage_decrypted();
    void set_secret_unlocked(bool value);
    void set_storage_decrypted(bool value);
private:
    bool secret_unlocked;
    bool storage_decrypted;
};
#endif
