//==================================================================================================
// Project : Teensy HSM
// Author  : Edi Permadi
// Repo    : https://github.com/edipermadi/teensy-hsm
//
// This file is part of TeensyHSM project containing the implementation of AES-128 based CTR_DRBG
// deterministic random bit generator seeded by whitened ADC noise.
//==================================================================================================

//--------------------------------------------------------------------------------------------------
// Includes
//--------------------------------------------------------------------------------------------------
#include <ADC.h>
#include "drbg.h"

static void ctr_drbg_init  (drbg_ctx_t *ctx, uint8_t *entropy);
static void ctr_drbg_update(drbg_ctx_t *ctx);
static void ctr_drbg_reseed(drbg_ctx_t *ctx, uint8_t *entropy, uint8_t *input);
static uint8_t ctr_drbg_generate(drbg_ctx_t *ctx, uint8_t *output, uint16_t length);

//--------------------------------------------------------------------------------------------------
// Hardare Configuration
//--------------------------------------------------------------------------------------------------
#define PIN_ADC1 A9
#define PIN_ADC2 A9

//--------------------------------------------------------------------------------------------------
// GLobal variables
//--------------------------------------------------------------------------------------------------
static ADC *adc = new ADC();
static FastCRC32 CRC32;
static drbg_ctx_t drbg_ctx;

//--------------------------------------------------------------------------------------------------
// DRBG functions
//--------------------------------------------------------------------------------------------------
void drbg_init() {
  uint8_t entropy[THSM_CTR_DRBG_SEED_SIZE];

  /* init adc */
  adc_init();

  /* get entropy from adc */
  adc_rng_read(entropy, sizeof(entropy));
  ctr_drbg_init(&drbg_ctx, entropy);

  /* clear entorpy buffer */
  memset(entropy, 0, sizeof(entropy));
}

uint8_t drbg_read(uint8_t *buffer, uint16_t length)
{
  return ctr_drbg_generate(&drbg_ctx, buffer, length);
}

void drbg_reseed(uint8_t *seed) {
  uint8_t entropy[THSM_CTR_DRBG_SEED_SIZE];

  /* get entropy*/
  adc_rng_read(entropy, sizeof(entropy));

  ctr_drbg_reseed(&drbg_ctx, entropy, seed);

  /* clear entorpy buffer */
  memset(entropy, 0, sizeof(entropy));
}

//--------------------------------------------------------------------------------------------------
// AES-CTR DRBG functions
//--------------------------------------------------------------------------------------------------
static void ctr_drbg_init(drbg_ctx_t *ctx, uint8_t *entropy) {
  memset(ctx, 0, sizeof(drbg_ctx_t));
  memcpy(ctx->counter, entropy, sizeof(ctx->counter));
  ctr_drbg_update(ctx);

  /* set counter to 1 */
  memset(ctx->counter, 0, sizeof(ctx->counter));
  ctx->counter[sizeof(ctx->counter) - 1] = 1;
}

static void ctr_drbg_update(drbg_ctx_t *ctx) {
  uint8_t ciphertext[THSM_CTR_DRBG_SEED_SIZE];
  uint8_t *ptr1 = ciphertext;
  uint8_t *ptr2 = ciphertext + THSM_BLOCK_SIZE;

  drbg_state_inc(ctx->value, 1);
  aes_ecb_encrypt(ptr1, ctx->value, ctx->key, THSM_KEY_SIZE);
  drbg_state_inc(ctx->value, 1);
  aes_ecb_encrypt(ptr2, ctx->value, ctx->key, THSM_KEY_SIZE);

  /* xor ciphertext with data */
  for (uint16_t i = 0; i < sizeof(ciphertext); i++) {
    ciphertext[i] ^= ctx->counter[i];
  }

  /* store computed value */
  memcpy(ctx->key,   ptr1, THSM_BLOCK_SIZE);
  memcpy(ctx->value, ptr2, THSM_BLOCK_SIZE);
}

static void ctr_drbg_reseed(drbg_ctx_t *ctx, uint8_t *entropy, uint8_t *input) {
  /* fill counter*/
  for (uint16_t i = 0; i < sizeof(ctx->counter); i++) {
    ctx->counter[i] = *entropy ^ *input++;
  }

  /* update key and value */
  ctr_drbg_update(ctx);

  /* set counter to 1 */
  memset(ctx->counter, 0, sizeof(ctx->counter));
  ctx->counter[sizeof(ctx->counter) - 1] = 1;
}

static uint8_t ctr_drbg_generate(drbg_ctx_t *ctx, uint8_t *output, uint16_t length) {
  uint32_t counter = read_uint32(ctx->counter + 8);

  /* reseed required */
  if (counter >= 0x10000) {
    return 0;
  }

  uint8_t buffer[THSM_BLOCK_SIZE];
  /* generate random number */
  while (length > 0) {
    uint8_t step = (length > THSM_BLOCK_SIZE) ? THSM_BLOCK_SIZE : length;
    drbg_state_inc(ctx->value, 1);
    memset(buffer, 0, sizeof(buffer));
    aes_ecb_encrypt(buffer, ctx->value, ctx->key, THSM_KEY_SIZE);
    memcpy(output, buffer, step);

    /* update output pointer and length counter */
    output += step;
    length -= step;
  }

  /* update request counter */
  drbg_state_inc(ctx->counter + THSM_BLOCK_SIZE, 1);
  return 1;
}

static uint8_t drbg_state_inc(uint8_t *value, uint8_t ov) {
  /* load */
  uint32_t v0 = read_uint32(value);
  uint32_t v1 = read_uint32(value +  4);
  uint32_t v2 = read_uint32(value +  8);
  uint32_t v3 = read_uint32(value + 12);

  /* update */
  v3 += ov; ov = (v3 == 0);
  v2 += ov; ov = (v2 == 0);
  v1 += ov; ov = (v1 == 0);
  v0 += ov; ov = (v0 == 0);

  /* store */
  write_uint32(value,      v0);
  write_uint32(value +  4, v1);
  write_uint32(value +  8, v2);
  write_uint32(value + 12, v3);
  return ov;
}

//--------------------------------------------------------------------------------------------------
// ADC
//--------------------------------------------------------------------------------------------------
static void adc_init() {
  pinMode(PIN_ADC1, INPUT); //pin 23 single ended
  pinMode(PIN_ADC2, INPUT); //pin 23 single ended

  adc->setReference(ADC_REFERENCE::REF_1V2, ADC_0);
  adc->setReference(ADC_REFERENCE::REF_1V2, ADC_1);
  adc->setSamplingSpeed(ADC_SAMPLING_SPEED::HIGH_SPEED);
}

static uint8_t adc_read()
{
  int ret = ADC_ERROR_VALUE;
  while (ret == ADC_ERROR_VALUE) {
    ret = adc->analogRead(A9, ADC_0);
  }
  return ret;
}

static uint32_t adc_rng_step() {
  uint8_t buffer[16];

  /* fill buffer */
  for (uint16_t i = 0; i < sizeof(buffer); i++) {
    buffer[i] = adc_read();
  }

  return CRC32.crc32(buffer, sizeof(buffer));
}

static void adc_rng_read(uint8_t *p_buffer, uint16_t len)
{
  word_t data;
  uint16_t idx = 4;

  while (len--)
  {
    if (idx == 4)
    {
      data.words = adc_rng_step();
      idx = 0;
    }

    *p_buffer++ = data.bytes[idx++];
  }
}
