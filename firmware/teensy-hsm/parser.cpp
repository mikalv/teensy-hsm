#include <string.h>
#include "parser.h"
#include "macros.h"

#define STATE_WAIT_BCNT     0
#define STATE_WAIT_CMD      1
#define STATE_WAIT_PAYLOAD  2

Parser::Parser()
{
    clear();
}

Parser::~Parser()
{
    clear();
}

void Parser::init()
{
    clear();
}

void Parser::clear()
{
    command_id = 0;
    state = STATE_WAIT_BCNT;
    null_counter = 0;
    remaining = 0;
    MEMCLR(request);
    MEMCLR(response);

}
void Parser::process(uint8_t byte)
{
    null_counter += (byte == 0);
    if (null_counter == THSM_MAX_PKT_SIZE)
    {
        clear();
        return;
    }

    bool execute = false;
    switch (state)
    {
    case STATE_WAIT_BCNT:
        if (byte > 0)
        {
            state = STATE_WAIT_CMD;
            remaining = byte;
        }
        break;

    case STATE_WAIT_CMD:
        command_id = byte;
        MEMCLR(request);
        if (--remaining > 0)
        {
            state = STATE_WAIT_PAYLOAD;
        }
        else
        {
            execute = true;
        }
        break;

    case STATE_WAIT_PAYLOAD:
        request.bytes[request.length] = byte;
        if (--remaining > 0)
        {
            state = STATE_WAIT_PAYLOAD;
        }
        else
        {
            execute = true;
        }
        break;
    }

    if (execute)
    {
        if (commands.process(command_id, response, request))
        {
#ifdef CORE_TEENSY_SERIAL
            Sertial.write((response.length + 1), BYTE);
            Sertial.write(command_id | THSM_FLAG_RESPONSE, BYTE);
            Serial.write(response.bytes, response.length);
#endif
        }

        clear();
    }
}
