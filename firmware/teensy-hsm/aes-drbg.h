#ifndef __DRBG_H__
#define  __DRBG_H

//------------------------------------------------------------------------------
// Imports
//------------------------------------------------------------------------------
#include <stdint.h>
#include "sizes.h"

//------------------------------------------------------------------------------
// Data Structure
//------------------------------------------------------------------------------
typedef struct {
  uint8_t value   [THSM_BLOCK_SIZE];
  uint8_t key     [THSM_BLOCK_SIZE];
  uint8_t counter [THSM_CTR_DRBG_SEED_SIZE];
} drbg_ctx_t;

#endif
