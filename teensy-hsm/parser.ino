//--------------------------------------------------------------------------------------------------
// Debugging compilation flag
//--------------------------------------------------------------------------------------------------
#define DEBUG_CONSOLE       1

//--------------------------------------------------------------------------------------------------
// States
//--------------------------------------------------------------------------------------------------
#define STATE_WAIT_BCNT     0
#define STATE_WAIT_CMD      1
#define STATE_WAIT_PAYLOAD  2

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------
void parser_reset() {
  memset(&request,       0, sizeof(request));
  memset(&response,      0, sizeof(response));
}

void parser_init() {
  Serial.begin(9600);
  parser_reset();
}

void parser_run() {
  uint8_t idx       = 0;
  uint8_t remaining = 0;
  uint8_t state     = STATE_WAIT_BCNT;
  uint8_t zero_ctr  = 0;
#if DEBUG_CONSOLE > 0
  uint8_t tab_ctr   = 0;
#endif

  while (1) {
    if (Serial.available()) {
      // read character from USB
      uint8_t b = Serial.read();

#if DEBUG_CONSOLE > 0
      /* detect debug */
      tab_ctr  = (b == '\t') ? (tab_ctr + 1) : 0;
#endif

      /* detect reset */
      zero_ctr = (!b) ? (zero_ctr + 1) : 0;
      if (zero_ctr == THSM_MAX_PKT_SIZE)
      {
        parser_reset();
        zero_ctr = 0;
        tab_ctr  = 0;
        state = STATE_WAIT_BCNT;
        continue;
      }
#if DEBUG_CONSOLE > 0
      else if (tab_ctr == '\t') {
        debug_run();

        /* reset parser */
        parser_reset();
        zero_ctr = 0;
        tab_ctr  = 0;
        state = STATE_WAIT_BCNT;
        continue;
      }
#endif

      // dispatch state
      switch (state)
      {
        case STATE_WAIT_BCNT:
          request.bcnt = (b > (THSM_MAX_PKT_SIZE + 1)) ? (THSM_MAX_PKT_SIZE + 1) : b;
          remaining = b;
          state = STATE_WAIT_CMD;
          break;

        case STATE_WAIT_CMD:
          if (remaining-- > 0)
          {
            request.cmd = b;
            if (!remaining)
            {
              execute_cmd();
              zero_ctr = 0;
              state = STATE_WAIT_BCNT;
            }
            else
            {
              idx = 0;
              state = STATE_WAIT_PAYLOAD;
            }
          }
          else
          {
            zero_ctr = 0;
            state = STATE_WAIT_BCNT;
          }
          break;

        case STATE_WAIT_PAYLOAD:
          if (remaining-- > 0)
          {
            /* cap index by THSM_MAX_PKT_SIZE */
            if (idx < THSM_MAX_PKT_SIZE) {
              request.payload.raw[idx++] = b;
            }
          }

          if (!remaining)
          {
            execute_cmd();
            parser_reset();
            zero_ctr = 0;
            state = STATE_WAIT_BCNT;
          }
          break;
      }
    }
  }
}
