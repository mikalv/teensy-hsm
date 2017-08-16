#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "storage.h"
#include "sha1-hmac.h"

#define KEY_HANDLE 0xaaaaaaaa

static void hexdump(const char * title, uint8_t *data, uint32_t length)
{
    printf("%s : ", title);
    for (int i = 0; i < length; i++)
    {
        printf("%02x%c", data[i], (i + 1) % 32 ? ' ' : '\n');
    }
    putchar('\n');
}

int main(void)
{
    aes_state_t key, iv;
    key_info_t key_info;
    secret_info_t secret_info;
    aes_ccm_nonce_t public_id;

    memset(key.bytes, 0, sizeof(key.bytes));
    memset(iv.bytes, 0, sizeof(iv.bytes));
    memset(key_info.bytes, 0, sizeof(key_info));
    memset(secret_info.uid, 0x11, sizeof(secret_info.uid));
    memset(secret_info.key, 0x22, sizeof(secret_info.key));
    memset(public_id.bytes, 0x33, sizeof(public_id.bytes));

    key_info.flags = 0x55555555;
    key_info.handle = KEY_HANDLE;
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
        exit(1);
    }

    if (storage.put_secret(secret_info, KEY_HANDLE, public_id) < 0)
    {
        printf("failed to put secret\n");
        exit(1);
    }
    storage.store(key, iv);

    /* load and dump */
    storage.clear();
    if (storage.load(key, iv) < 0)
    {
        printf("failed to load storage");
        exit(1);
    }

    secret_info_t recovered_secret;
    if (storage.get_secret(recovered_secret, KEY_HANDLE, public_id) < 0)
    {
        printf("failed to get secret\n");
        exit(1);
    }

    bool key_matched = memcmp(recovered_secret.key, secret_info.key, sizeof(secret_info.key)) == 0;
    bool uid_matched = memcmp(recovered_secret.uid, secret_info.uid, sizeof(secret_info.uid)) == 0;
    printf("key_matched = %d, uid_matched = %d\n", key_matched, uid_matched);
#ifdef DEBUG_STORAGE
    storage.dump_keys();
#endif
}
