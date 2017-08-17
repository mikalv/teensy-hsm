#include <stdio.h>
#include <string.h>
#include "aes-drbg.h"


static void hexdump(char *buffer, const uint8_t *values, size_t length)
{
    for (int i = 0; i < length; i++, buffer += 2)
    {
        sprintf(buffer, "%02x", values[i]);
    }
}

int main(void)
{
    char buffer[128];
    aes_drbg_entropy_t entropy;
    memset(entropy.bytes, 0x5a, sizeof(entropy.bytes));

    AESDRBG drbg = AESDRBG();
    drbg.init(entropy);

    for(int i=0;i<16;i++){
        aes_state_t random;
        drbg.generate(random);

        hexdump(buffer, random.bytes, sizeof(random.bytes));
        printf("random #%d : %s\n", i, buffer);
    }

    return 0;
}
