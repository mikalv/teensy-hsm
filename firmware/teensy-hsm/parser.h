#ifndef __PARSER_H__
#define __PARSER_H__

#include <stdint.h>
#include "commands.h"

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

class Parser
{
public:
    Parser();
    ~Parser();
    void init();
    void clear();
    void process(uint8_t byte);
private:
    uint32_t null_counter;
    uint32_t remaining;
    uint32_t state;

    uint32_t command_id;
    packet_t request;
    packet_t response;

    Commands commands;
};
#endif
