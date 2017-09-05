#include <string.h>
#include "nonce.h"
#include "macros.h"

void Nonce::get_and_increment(uint8_t *buffer, uint32_t step)
{
    memcpy(buffer, counter, sizeof(counter));
    if (step < 1)
    {
        return;
    }

    uint16_t hi = READ16(counter);
    uint32_t lo = READ32(counter + 2);
    uint32_t tmp = lo + step;
    hi += (tmp < lo) ? 1 : 0;
    lo = tmp;

    WRITE16(counter, hi);
    WRITE32(counter + 2, lo);
}
