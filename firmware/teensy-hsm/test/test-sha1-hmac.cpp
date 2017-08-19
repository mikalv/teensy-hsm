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

static void hmac_equals(const uint8_t *data, uint32_t data_length, const uint8_t *key, uint32_t key_length,
        const sha1_digest_t &expected, const char *hex_msg, const char *hex_key)
{
    sha1_digest_t actual;
    SHA1HMAC hmac = SHA1HMAC();
    hmac.calculate(actual, data, data_length, key, key_length);

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
    {  4, "4a656665"                                , 28, "7768617420646f2079612077616e7420666f72206e6f7468696e673f", "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"},
    { 20, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 50, "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", "125d7342b9ac11cd91a39af48aa17b4f63f175d3"},
    { 25, "0102030405060708090a0b0c0d0e0f10111213141516171819", 50, "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd", "4c9007f4026250c6bc8414f9bf50c86c2d7235da"},
    { 20, "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c", 20, "546573742057697468205472756e636174696f6e", "4c1a03424b55e07fe7f27be1d58bb9324a9a5a04"},
    { 80, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 54, "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374", "aa4ae5e15272d00e95705637ce8a3b55ed402112"},
    { 80, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 73, "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b657920616e64204c6172676572205468616e204f6e6520426c6f636b2d53697a652044617461", "e8e99d0f45237d786d6bbaa7965c7808bbff1a91"},
    { 80, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 54, "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374", "aa4ae5e15272d00e95705637ce8a3b55ed402112"},
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
        decode(buffer_key, values[i].key, key_len);
        decode(buffer_message, values[i].message, message_len);
        decode(mac.bytes, values[i].mac, sizeof(mac.bytes));

        hmac_equals(buffer_message, message_len, buffer_key, key_len, mac, values[i].message, values[i].key);
    }
}

