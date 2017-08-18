#ifndef __HSM_H__
#define __HSM_H__

#include <stdint.h>
#include "commands.h"

#define THSM_MAX_PKT_SIZE        0x60 // Max size of a packet (excluding command byte)

typedef struct
{
    uint8_t bcnt;
    uint8_t cmd;
    uint8_t payload[THSM_MAX_PKT_SIZE];
} THSM_PKT_REQ;

typedef struct
{
    uint8_t bcnt;
    uint8_t cmd;
    uint8_t payload[THSM_MAX_PKT_SIZE];
} THSM_PKT_RESP;

class HSM
{
public:
    HSM();
    void init();
    void run();
private:
    THSM_PKT_REQ request;
    THSM_PKT_REQ response;
    Commands commands;
};
#endif
