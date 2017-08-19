#include <stdio.h>
#include "debug.h"

void hexdump(const char * title, const uint8_t *data, uint32_t length)
{
    printf("%s", title);
    for (int i = 0; i < length; i++)
    {
        printf("%02x%c", data[i], ((i + 1) % 32) ? ' ' : '\n');
    }
    printf("\n\n");
}
