//==================================================================================================
// Project : Teensy HSM
// Author  : Edi Permadi
// Repo    : https://github.com/edipermadi/teensy-hsm
//
// This file is part of TeensyHSM project containing the implementation LED visual interface.
//==================================================================================================

//--------------------------------------------------------------------------------------------------
// Hardare Configuration
//--------------------------------------------------------------------------------------------------
#define PIN_LED  13

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------
void led_init() {
  pinMode(PIN_LED, OUTPUT);
}

void led_on() {
  /* switch on LED */
  digitalWrite(PIN_LED, HIGH);
}

void led_off() {
  /* switch off LED */
  digitalWrite(PIN_LED, LOW);
}
