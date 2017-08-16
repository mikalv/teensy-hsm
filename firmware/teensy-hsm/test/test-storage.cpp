#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "storage.h"
#include "sha1-hmac.h"

static void hexdump(const char * title, uint8_t *data, uint32_t length){
    printf("%s : ", title);
    for(int i=0;i<length;i++){
        printf("%02x%c", data[i], (i+1) % 32 ? ' ' : '\n');
    }
    putchar('\n');
}

int main(void)
{
    aes_state_t key, iv;
    key_info_t key_info;
    memset(key.bytes, 0, sizeof(key.bytes));
    memset(iv.bytes, 0, sizeof(iv.bytes));
    memset(key_info.bytes, 0, sizeof(key_info));

    key_info.flags = 0x55555555;
    key_info.handle = 0xaaaaaaaa;
    memset(key_info.bytes, 0xa5, sizeof(key_info.bytes));

    /* format and load */
    Storage storage = Storage();
    storage.format(key, iv);

    /* load */
    storage.clear();
    if (storage.load(key, iv) < 0)
    {
        printf("failed to load storage");
        exit(1);
    }

    /* put key and store */
    if (storage.put_key(key_info) < 0)
    {
        printf("failed to put key\n");
    }
    storage.store(key, iv);

    /* load and dump */
    storage.clear();
    if (storage.load(key, iv) < 0)
    {
        printf("failed to load storage");
        exit(1);
    }
#ifdef DEBUG_STORAGE
    storage.dump_keys();
#endif
}
