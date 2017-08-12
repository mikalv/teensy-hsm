#include <string.h>
#include "buffer.h"

THSM_BUFFER thsm_buffer;

void buffer_init(){
        memset(&thsm_buffer, 0, sizeof(thsm_buffer));
}
