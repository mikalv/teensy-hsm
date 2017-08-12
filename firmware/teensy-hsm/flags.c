#include <stdint.h>
#include "flags.h"

//------------------------------------------------------------------------------
// Global Variables
//------------------------------------------------------------------------------
static uint32_t system_flags;

//------------------------------------------------------------------------------
// System Flags Definition
//------------------------------------------------------------------------------
#define SYSTEM_FLAGS_STORAGE_INITIALIZED  (1 << 0)
#define SYSTEM_FLAGS_STORAGE_DECRYPTED    (1 << 1)
#define SYSTEM_FLAGS_SECRET_UNLOCKED      (1 << 2)

//------------------------------------------------------------------------------
// Functions
//------------------------------------------------------------------------------
void flags_set_secret_locked(uint8_t value) {
        if (value) {
                system_flags &= ~SYSTEM_FLAGS_SECRET_UNLOCKED;
        } else {
                system_flags |= SYSTEM_FLAGS_SECRET_UNLOCKED;
        }
}

void flags_set_storage_encrypted(uint8_t value) {
        if (value) {
                system_flags &= ~SYSTEM_FLAGS_STORAGE_DECRYPTED;
        } else {
                system_flags |= SYSTEM_FLAGS_STORAGE_DECRYPTED;
        }
}

uint8_t flags_is_secret_locked(){
        return !(system_flags & SYSTEM_FLAGS_SECRET_UNLOCKED);
}

uint8_t flags_is_storage_decrypted(){
        return !(system_flags & SYSTEM_FLAGS_STORAGE_DECRYPTED);
}
