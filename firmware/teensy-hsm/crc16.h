#ifndef __CRC16_H__
#define __CRC16_H__

#include <stdint.h>

class CRC16{
public:
    CRC16();
    uint16_t ccit(const uint8_t *data, uint32_t length);
};
#endif
