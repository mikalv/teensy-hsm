//==================================================================================================
// Project : Teensy HSM
// Author  : Edi Permadi
// Repo    : https://github.com/edipermadi/teensy-hsm
//
// This file is part of TeensyHSM project containing the implementation nonce pool
//==================================================================================================

//--------------------------------------------------------------------------------------------------
// Global Variables
//--------------------------------------------------------------------------------------------------
static uint8_t nonce_pool[THSM_AEAD_NONCE_SIZE];

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------
void nonce_pool_init() {
  /* fill nonce pool */
  drbg_read(nonce_pool, sizeof(nonce_pool));
}

void nonce_pool_read(uint8_t *buffer, uint16_t step) {
  /* copy nonce pool to buffer */
  memcpy(buffer, nonce_pool, THSM_AEAD_NONCE_SIZE);

  /* increment pool */
  while (step--) {
    nonce_pool_increment();
  }
}

static void nonce_pool_increment() {
  increment_nonce(nonce_pool);
}

