#ifndef __DEBUG_H__
#define __DEBUG_H__

#include <stdint.h>
#include <stdio.h>

void hexdump(const char * title, const uint8_t *data, uint32_t length);

#endif
