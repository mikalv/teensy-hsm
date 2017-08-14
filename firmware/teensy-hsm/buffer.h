#ifndef __BUFFER_H__
#define __BUFFER_H__

//------------------------------------------------------------------------------
// Imports
//------------------------------------------------------------------------------
#include <stdint.h>
#include <string.h>
#include "sizes.h"
#include "macros.h"

#define BUFFER_SIZE_BYTES   72

//------------------------------------------------------------------------------
// Data Structure
//------------------------------------------------------------------------------
typedef struct {
    uint8_t data_len;
    uint8_t data[THSM_DATA_BUF_SIZE];
} THSM_BUFFER;

typedef struct buffer_t {
public:
    buffer_t(uint8_t *bytes, uint32_t length) {
        this->bytes = bytes;
        this->length = length;
    }

    uint8_t *bytes;
    uint32_t length;
} buffer_t;

//------------------------------------------------------------------------------
// Function Prototypes
//------------------------------------------------------------------------------
void buffer_init();

#endif
