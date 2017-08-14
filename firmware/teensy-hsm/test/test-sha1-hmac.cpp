#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sha1-hmac.h"

// Reference:
// https://tools.ietf.org/html/rfc2202

typedef struct
{
    size_t key_len;
    const char *key;
    size_t message_len;
    const char *message;
    const char *mac;
} test_vector_t;


static void hexdump(char *buffer, const uint8_t *values, size_t length)
{
    for (int i = 0; i < length; i++, buffer += 2)
    {
        sprintf(buffer, "%02x", values[i]);
    }
}

static void decode(uint8_t *buffer, const char *values, size_t length)
{
    for (int i = 0; i < length; i++, values += 2)
    {
        sscanf(values, "%2hhx", &buffer[i]);
    }
}

static void hmac_equals(const buffer_t &data, const buffer_t &key, const sha1_digest_t &expected, const char *hex_msg, const char *hex_key)
{
    sha1_digest_t actual;
    SHA1HMAC hmac = SHA1HMAC(key);
    hmac.update(data);
    hmac.final(actual);

    char buffer[64];
    hexdump(buffer, actual.bytes, sizeof(actual.bytes));

    bool success = (memcmp(actual.bytes, expected.bytes, sizeof(expected.bytes)) == 0);
    printf("TEST sha1_hmac(%s,%s) -> %s [%s]\n", hex_msg, hex_key, buffer, success ? "PASSED" : "FAILED");
    if (!success)
    {
        exit(1);
    }
}

int main(void)
{
    test_vector_t values[] =
    {
    { 20, "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", 8, "4869205468657265", "b617318655057264e28bc0b6fb378c8ef146be00" },
    {  4, "4a656665"                                , 28, "7768617420646f2079612077616e742666f72206e6f7468696e673f", "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"},
    };

    int tests = sizeof(values) / sizeof(values[0]);
    for (int i = 0; i < tests; i++)
    {
        uint8_t buffer_key[128];
        uint8_t buffer_message[128];
        sha1_digest_t mac;
        size_t key_len = values[i].key_len;
        size_t message_len = values[i].message_len;

        /* decode key and message */
        buffer_t key = buffer_t(buffer_key, key_len);
        buffer_t message = buffer_t(buffer_message, message_len);
        decode(buffer_key, values[i].key, key_len);
        decode(buffer_message, values[i].message, message_len);
        decode(mac.bytes, values[i].mac, sizeof(mac.bytes));

        hmac_equals(message,key, mac, values[i].message, values[i].key);
    }
}

