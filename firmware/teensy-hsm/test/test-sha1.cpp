#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sha1.h"

typedef struct
{
    const char *message;
    const char *digest;
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

static void digest_equals(const uint8_t *data, uint32_t data_length, const sha1_digest_t &expected, const char * title)
{
    sha1_digest_t actual;
    SHA1 sha1 = SHA1();
    sha1.update(data, data_length);
    sha1.final(actual);

    char buffer[64];
    hexdump(buffer, actual.bytes, sizeof(actual.bytes));

    bool success = (memcmp(actual.bytes, expected.bytes, sizeof(expected.bytes)) == 0);
    printf("TEST sha1('%s') -> %s [%s]\n", title, buffer, success ? "PASSED" : "FAILED");
    if (!success)
    {
        exit(1);
    }
}

int main(void)
{
    test_vector_t values[] = {
        { "abc", "a9993e364706816aba3e25717850c26c9cd0d89d" },
        { "", "da39a3ee5e6b4b0d3255bfef95601890afd80709" },
        { "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "84983e441c3bd26ebaae4aa1f95129e5e54670f1" },
        { "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", "a49b2446a02c645bf419f995b67091253a04a259" },
        { "the quick brown fox jumps over the lazy dog", "16312751ef9307c3fd1afbcb993cdc80464ba0f1"}
    };

    int tests = sizeof(values) / sizeof(values[0]);
    for (int i = 0; i < tests; i++)
    {
        const char *message = values[i].message;
        uint32_t length = strlen(message);
        sha1_digest_t expected;

        decode(expected.bytes, values[i].digest, sizeof(expected.bytes));
        digest_equals((const uint8_t *)message, length, expected, message);
    }
}
