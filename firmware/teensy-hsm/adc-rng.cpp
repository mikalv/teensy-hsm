#include "adc-rng.h"

ADCRNG::ADCRNG()
{
    pinMode(PIN_ADC1, INPUT); //pin 23 single ended
    pinMode(PIN_ADC2, INPUT); //pin 23 single ended

    adc.setReference(ADC_REFERENCE::REF_1V2, ADC_0);
    adc.setReference(ADC_REFERENCE::REF_1V2, ADC_1);
    adc.setSamplingSpeed(ADC_SAMPLING_SPEED::HIGH_SPEED);
}
