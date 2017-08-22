#include <string.h>
#include "hsm.h"
#include "macros.h"

#define STATE_WAIT_BCNT     0
#define STATE_WAIT_CMD      1
#define STATE_WAIT_PAYLOAD  2

HSM::HSM()
{
}

void HSM::init()
{
}

void HSM::clear()
{
    command_id = 0;
    state = STATE_WAIT_BCNT;
    null_counter = 0;
    remaining = 0;
    MEMCLR(request);
    MEMCLR(response);

}
void HSM::process(uint8_t byte)
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
        break;
    }

    if(execute){
        if(commands.process(command_id, response, request)){
            /* FIXME send response */
        }

        clear();
    }
}
