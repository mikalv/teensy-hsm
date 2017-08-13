#include <stdio.h>
#include <string.h>
#include "sha1.h"

static int digest_equals(const void *message, size_t length, const char *expected)
{
    sha1_digest_t actual;
    SHA1 sha1 = SHA1();
    sha1.update((uint8_t *) message, length);
    sha1.final(actual);

    char buffer[1024];
    char *ptr = buffer;
    memset(buffer, 0, sizeof(buffer));
    for (int i = 0; i < sizeof(actual.bytes); i++, ptr += 2)
    {
        sprintf(ptr, "%02x", actual.bytes[i]);
    }
    return strncmp(buffer, expected, 40) == 0;
}

static void expect(int success, const char * title)
{
    if (success > 0)
    {
        printf("TEST sha1('%s') passed\n", title);
    }
    else
    {
        printf("TEST sha1('%s') failed\n", title);
    }
}

typedef struct
{
    const char *message;
    const char *digest;
} test_vector_t;

int main(void)
{
    test_vector_t values[] =
    {
    { "abc", "a9993e364706816aba3e25717850c26c9cd0d89d" },
    { "", "da39a3ee5e6b4b0d3255bfef95601890afd80709" },
    { "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "84983e441c3bd26ebaae4aa1f95129e5e54670f1" },
    { "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopq"
            "rstu", "a49b2446a02c645bf419f995b67091253a04a259" } };

    int tests = sizeof(values) / sizeof(values[0]);
    for (int i = 0; i < tests; i++)
    {
        const char *message = values[i].message;
        const char *digest = values[i].digest;
        size_t length = strlen(message);
        expect(digest_equals(message, length, digest), message);
    }
}
