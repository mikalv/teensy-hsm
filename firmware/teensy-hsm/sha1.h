#ifndef __SHA1_H__
#define __SHA1_H__

#include <stdint.h>
#include "buffer.h"

/**
   DEFINITIONS
*/
#define SHA1_DIGEST_SIZE_BITS    160
#define SHA1_DIGEST_SIZE_BYTES   (SHA1_DIGEST_SIZE_BITS / 8)
#define SHA1_DIGEST_SIZE_WORDS   (SHA1_DIGEST_SIZE_BYTES / sizeof(uint32_t))
#define SHA1_BLOCK_SIZE_BITS     512
#define SHA1_BLOCK_SIZE_BYTES    (SHA1_BLOCK_SIZE_BITS / 8)
#define SHA1_BLOCK_SIZE_WORDS    (SHA1_BLOCK_SIZE_BYTES / sizeof(uint32_t))

//------------------------------------------------------------------------------
// Data Structures
//------------------------------------------------------------------------------

typedef struct {
  uint8_t bytes[SHA1_BLOCK_SIZE_BYTES];
  uint32_t length;
} sha1_buffer_t;

typedef struct {
  uint8_t bytes[SHA1_DIGEST_SIZE_BYTES];
} sha1_digest_t;

typedef struct {
  sha1_buffer_t buffer;
  uint32_t hashes[SHA1_DIGEST_SIZE_WORDS];
  uint32_t words[80];
  uint64_t msg_length;
} sha1_ctx_t;

//------------------------------------------------------------------------------
// Function Prototypes
//------------------------------------------------------------------------------
uint8_t sha1_compare(uint8_t *data, uint16_t data_len, uint8_t *digest);
void sha1_calculate(uint8_t *data, uint16_t data_len, uint8_t *digest);

class SHA1 {
  public:
    SHA1();
    ~SHA1();
    void reset();
    int32_t update(const buffer_t &data);
    void final(sha1_digest_t &digest);
    int32_t calculate(sha1_digest_t &digest, const buffer_t &data);
    bool compare(const buffer_t &data, const sha1_digest_t &reference);
  private:
    void step();
    sha1_ctx_t ctx;
};
#endif
