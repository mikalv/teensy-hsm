#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "storage.h"
#include "sha1-hmac.h"

#define KEY_HANDLE 0xaaaaaaaa

int main(void)
{
    int32_t ret;
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

    printf("formatting storage\n");
    storage.format(key, iv);

    /* load */
    storage.clear();

    ret = storage.load(key, iv);
    if (ret < 0)
    {
        printf("failed to load storage (error %d)\n", ret);
        exit(1);
    }

    /* put key and store */
    ret = storage.put_key(key_info);
    if (ret < 0)
    {
        printf("failed to put key (error %d)\n", ret);
        exit(1);
    }

    ret = storage.put_secret(secret_info, KEY_HANDLE, public_id);
    if (ret < 0)
    {
        printf("failed to put secret (error %d)\n", ret);
        exit(1);
    }
    storage.store(key, iv);

    /* load and dump */
    storage.clear();
    ret = storage.load(key, iv);
    if (ret < 0)
    {
        printf("failed to load storage (error %d)\n", ret);
        exit(1);
    }

    secret_info_t recovered_secret;
    ret = storage.get_secret(recovered_secret, KEY_HANDLE, public_id);
    if (ret < 0)
    {
        printf("failed to get secret (error %d)\n", ret);
        exit(1);
    }

    bool key_matched = memcmp(recovered_secret.key, secret_info.key, sizeof(secret_info.key)) == 0;
    bool uid_matched = memcmp(recovered_secret.uid, secret_info.uid, sizeof(secret_info.uid)) == 0;
    printf("key_matched = %d, uid_matched = %d\n", key_matched, uid_matched);
#ifdef DEBUG_STORAGE
    storage.dump_keys();
#endif
}
