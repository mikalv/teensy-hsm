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
  uint8_t ov = 1;

  nonce_pool[5] = + ov; ov = (nonce_pool[5] == 0);
  nonce_pool[4] = + ov; ov = (nonce_pool[4] == 0);
  nonce_pool[3] = + ov; ov = (nonce_pool[3] == 0);
  nonce_pool[2] = + ov; ov = (nonce_pool[2] == 0);
  nonce_pool[1] = + ov; ov = (nonce_pool[1] == 0);
  nonce_pool[0] = + ov; ov = (nonce_pool[0] == 0);
}

