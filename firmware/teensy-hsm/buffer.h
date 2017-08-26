#ifndef __BUFFER_H__
#define __BUFFER_H__

//------------------------------------------------------------------------------
// Imports
//------------------------------------------------------------------------------
#include <stdint.h>

#define BUFFER_SIZE_BYTES   64

//------------------------------------------------------------------------------
// Data Structure
//------------------------------------------------------------------------------
typedef struct buffer_t
{
    uint8_t bytes[BUFFER_SIZE_BYTES];
    uint32_t length;
} buffer_t;

//------------------------------------------------------------------------------
// Classes
//------------------------------------------------------------------------------
class Buffer
{
public:
    Buffer();
    ~Buffer();
    void init();
    void clear();
    void read(buffer_t &buffer);
    bool write(uint32_t offset, const uint8_t *data, uint32_t data_len);
private:
    uint32_t length;
    uint8_t bytes[BUFFER_SIZE_BYTES];
};

#endif
