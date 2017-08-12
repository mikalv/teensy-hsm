//==============================================================================
// Project : Teensy HSM
// Author  : Edi Permadi
// Repo    : https://github.com/edipermadi/teensy-hsm
//
// This file is part of TeensyHSM project containing the implementation of SHA1
//==============================================================================
#ifdef UNIT_TEST_SHA1
#include <stdio.h>
#endif

#include <string.h>
#include "macros.h"
#include "sha1.h"

//==============================================================================
// MACTOS
//==============================================================================
#define ROTL_1(x) (((x) << 1) | ((x) >> 31))
#define ROTL_5(x) (((x) << 5) | ((x) >> 27))
#define ROTL_30(x)(((x) << 30) | ((x) >> 2))

//==============================================================================
// IMPLEMENATIONS
//==============================================================================
SHA1::SHA1()
{
    reset();
}

SHA1::~SHA1()
{
    MEMSET(ctx);
}

void SHA1::reset()
{
    MEMSET(ctx);
    ctx.hashes[0] = 0x67452301;
    ctx.hashes[1] = 0xefcdab89;
    ctx.hashes[2] = 0x98badcfe;
    ctx.hashes[3] = 0x10325476;
    ctx.hashes[4] = 0xc3d2e1f0;
}

void SHA1::update(uint8_t *data, uint32_t length)
{
#define CAPACITY sizeof(ctx.buffer.bytes)

    /* update total length */
    ctx.msg_length += length;
    while (length > 0)
    {
        uint32_t written = ctx.buffer.length;
        if (written < CAPACITY)
        {
            uint32_t step = MIN(length, (CAPACITY - written));
            memcpy(ctx.buffer.bytes + written, data, step);

            data += step;
            length -= step;
            written += step;
            ctx.buffer.length += step;
        }

        if (written >= CAPACITY)
        {
            step();
        }
    }
#undef CAPACITY
}

void SHA1::final(sha1_digest_t &digest)
{
#define CAPACITY    sizeof(ctx.buffer.bytes)
#define OFFSET      (CAPACITY - sizeof(uint64_t))

    uint32_t written = ctx.buffer.length;

    /* append padding */
    ctx.buffer.bytes[written] = 0x80;
    memset(ctx.buffer.bytes + written + 1, 0, (CAPACITY - (written + 1)));

    if (written > (CAPACITY - 9))
    {
        step();
    }

    /* append length in bits */
    uint64_t msg_length = (ctx.msg_length << 3);
    uint8_t *ptr1 = ctx.buffer.bytes + OFFSET;
    WRITE64(ptr1, msg_length);

    /* run last round */
    step();

    uint8_t *ptr2 = digest.bytes;
    for (uint16_t i = 0; i < SHA1_DIGEST_SIZE_WORDS; i++)
    {
        WRITE32(ptr2, ctx.hashes[i]);
    }

    /* clear context */
    MEMSET(ctx);

#undef CAPACITY
#undef OFFSET
}

void SHA1::digest(sha1_digest_t &digest, uint8_t *data, uint32_t length)
{
    reset();
    update(data, length);
    final(digest);
}

bool SHA1::compare(uint8_t *data, uint32_t length, uint8_t *reference)
{
    sha1_digest_t actual;
    digest(actual, data, length);

    return memcmp(actual.bytes, reference, sizeof(actual.bytes)) == 0;
}

void SHA1::step()
{
    uint32_t words[SHA1_BLOCK_SIZE_WORDS];
    uint32_t a, b, c, d, e;

    /* load block */
    uint8_t *ptr = ctx.buffer.bytes;
    for (uint16_t i = 0; i < SHA1_BLOCK_SIZE_WORDS; i++, ptr += 4)
    {
        words[i] = READ32(ptr);
    }

    /* load hash */
    a = ctx.hashes[0];
    b = ctx.hashes[1];
    c = ctx.hashes[2];
    d = ctx.hashes[3];
    e = ctx.hashes[4];

    for (uint32_t i = 0; i < 80; i++)
    {
        uint32_t w, t;

        t = (i < 16) ? words[i] : ROTL_1(ctx.words[i - 3] ^ ctx.words[i - 8] ^ ctx.words[i - 14] ^ ctx.words[i - 16]);
        ctx.words[i] = t;

        if (i < 20)
        {
            w = ROTL_5(a) + ((b & c) | ((~b) & d)) + e + t + 0x5a827999;
        }
        else if (i < 40)
        {
            w = ROTL_5(a) + (b ^ c ^ d) + e + t + 0x6ed9eba1;
        }
        else if (i < 60)
        {
            w = ROTL_5(a) + ((b & c) | (b & d) | (c & d)) + e + t + 0x8f1bbcdc;
        }
        else
        {
            w = ROTL_5(a) + (b ^ c ^ d) + e + t + 0xca62c1d6;
        }

        e = d;
        d = c;
        c = ROTL_30(b);
        b = a;
        a = w;
    }

    /* store hash */
    ctx.hashes[0] += a;
    ctx.hashes[1] += b;
    ctx.hashes[2] += c;
    ctx.hashes[3] += d;
    ctx.hashes[4] += e;

    /* clear buffer */
    MEMSET(ctx.buffer);
}

#ifdef UNIT_TEST_SHA1

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
    test_vector_t
    values[] =
    {

        {   "abc", "a9993e364706816aba3e25717850c26c9cd0d89d"},
        {   "", "da39a3ee5e6b4b0d3255bfef95601890afd80709"},
        {   "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "84983e441c3bd26ebaae4aa1f95129e5e54670f1"},
        {   "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", "a49b2446a02c645bf419f995b67091253a04a259"}
    };

    int tests = sizeof(values) / sizeof(values[0]);
    for (int i = 0; i < tests; i++)
    {
        const char *message = values[i].message;
        const char *digest = values[i].digest;
        size_t length = strlen(message);
        expect(digest_equals(message, length, digest), message);
    }
}
#endif
