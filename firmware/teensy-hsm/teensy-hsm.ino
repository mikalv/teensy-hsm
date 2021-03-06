//==================================================================================================
// Project : Teensy HSM
// Author  : Edi Permadi
// Repo    : https://github.com/edipermadi/teensy-hsm
//
// This file is part of TeensyHSM project containing the the main entry point of the executable.
//==================================================================================================

//--------------------------------------------------------------------------------------------------
// Board Setup
//--------------------------------------------------------------------------------------------------
// Setup
// Board     : Teensy 3.1/3.2
// USB Type  : Serial
// CPU Speed : 72 MHz


//--------------------------------------------------------------------------------------------------
// Includes
//--------------------------------------------------------------------------------------------------
#include <ADC.h>
#include <EEPROM.h>

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------
#define THSM_PROTOCOL_VERSION       1
#define THSM_TEMP_KEY_HANDLE        0xffffffff

//--------------------------------------------------------------------------------------------------
// Data Structures
//--------------------------------------------------------------------------------------------------

typedef union {
  uint8_t  bytes[sizeof(uint32_t)];
  uint32_t words;
} word_t;

//--------------------------------------------------------------------------------------------------
// Global Variables
//--------------------------------------------------------------------------------------------------

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------
void setup() {
  system_flags = 0;

  led_init();
  drbg_init();
  parser_init();
  hmac_reset();
  keystore_init();
  buffer_init();

  /* init nonce pool */
  nonce_pool_init();
}

void loop() {
  parser_run();
}


