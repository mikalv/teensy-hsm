#include <stdio.h>
#include <string.h>
#include "storage.h"

int main(void)
{
    printf("hello world, %lu\n", sizeof(eeprom_layout_t));

    aes_state_t key, iv;
    key_info_t key_info;
    memset(key.bytes, 0, sizeof(key.bytes));
    memset(iv.bytes, 0, sizeof(iv.bytes));
    memset(key_info.bytes, 0, sizeof(key_info));

    key_info.flags = 0x55555555;
    key_info.handle = 0xaaaaaaaa;
    memset(key_info.bytes, 0xa5, sizeof(key_info.bytes));

    Storage storage = Storage();
    storage.format(key, iv);
#ifdef DEBUG_STORAGE
    //storage.dump_nv();
#endif

    /* load dump */
    storage.clear();
    storage.load(key, iv);
#ifdef DEBUG_STORAGE
    //storage.dump_keys();
#endif

    /* put key and store */
    storage.clear();
    if (storage.put_key(key_info) < 0)
    {
        printf("failed to put key\n");
    }
    storage.store(key, iv);
#ifdef DEBUG_STORAGE
    storage.dump_keys();
    storage.dump_nv();
#endif

    /* load and dump */
    storage.clear();
    storage.load(key, iv);
#ifdef DEBUG_STORAGE
    storage.dump_keys();
#endif
}
