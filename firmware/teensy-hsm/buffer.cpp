#include <string.h>
#include "buffer.h"
#include "macros.h"

Buffer::Buffer()
{
    clear();
}

Buffer::~Buffer()
{
    clear();
}

void Buffer::init()
{
    clear();
}

void Buffer::clear()
{
    length = 0;
    MEMCLR(bytes);
}

void Buffer::read(buffer_t &buffer)
{
    MEMCLR(buffer);
    memcpy(buffer.bytes, bytes, length);
    buffer.length = length;
}

bool Buffer::write(uint32_t offset, const uint8_t *data, uint32_t data_len)
{
    if ((offset > sizeof(bytes)) || (data_len > sizeof(bytes)))
    {
        return false;
    }

    uint32_t available = sizeof(bytes) - offset;
    uint32_t step = MIN(data_len, available);
    memcpy(bytes + offset, data, step);
    length = (step + offset);
    return true;
}
