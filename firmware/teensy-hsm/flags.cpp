#include "flags.h"

Flags::Flags()
{
    secret_unlocked = false;
    storage_decrypted = false;
}

bool Flags::is_secret_unlocked()
{
    return secret_unlocked;
}

bool Flags::is_storage_decrypted()
{
    return storage_decrypted;
}

void Flags::set_secret_unlocked(bool value)
{
    secret_unlocked = value;
}

void Flags::set_storage_decrypted(bool value)
{
    storage_decrypted = value;
}
