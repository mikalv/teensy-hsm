#ifndef __NONCE_H__
#define __NONCE_H__

#include <stdint.h>
class Nonce
{
public:
    void get_and_increment(uint8_t *buffer, uint32_t step);
private:
    uint8_t counter[6];
};

#endif /* NONCE_H_ */
