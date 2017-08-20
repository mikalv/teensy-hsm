#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crc16.h"

typedef struct
{
    const char *input;
    uint16_t output;
} value_t;

bool crc16_equals(const char *message, uint16_t reference)
{
    CRC16 crc16 = CRC16();
    uint16_t value = crc16.ccit((uint8_t *) message, strlen(message));
    bool passed = value == reference;
    printf("crc16('%s') -> 0x%04x (%s)\n", message, value, passed ? "PASSED" : "FAILED");
    return passed;
}

int main(void)
{
    const value_t values[] =
    {

    { "hello world", 0x39c1 },
    { "The quick brown fox jumps over the lazy dog", 0xfcdf },

    };

    for (int i = 0; i < sizeof(values) / sizeof(values[0]); i++)
    {
        if (!crc16_equals(values[i].input, values[i].output))
        {
            printf("failed to calculate crc of '%s'\n", values[i].input);
            exit(1);
        }
    }
}
