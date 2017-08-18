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

void Buffer::encode(buffer_t buffer)
{
}

int32_t Buffer::write(uint32_t offset, const uint8_t *data, uint32_t data_len)
{
}
