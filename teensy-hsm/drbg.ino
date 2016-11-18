//--------------------------------------------------------------------------------------------------
// Hardare Configuration
//--------------------------------------------------------------------------------------------------
#define PIN_ADC1 A9
#define PIN_ADC2 A9

//--------------------------------------------------------------------------------------------------
// GLobal variables
//--------------------------------------------------------------------------------------------------
static ADC *adc = new ADC();
static FastCRC32 CRC32;

//--------------------------------------------------------------------------------------------------
// DRBG functions
//--------------------------------------------------------------------------------------------------
void drbg_init() {
  adc_init();
}

void drbg_read(uint8_t *p_buffer, uint16_t len)
{
  word_t data;
  uint32_t idx = 4;

  while (len--)
  {
    if (idx == 4)
    {
      data.words = adc_rng_step();
      idx = 0;
    }

    *p_buffer++ = data.bytes[idx++];
  }
}

//--------------------------------------------------------------------------------------------------
// ADC
//--------------------------------------------------------------------------------------------------
static void adc_init() {
  pinMode(PIN_ADC1, INPUT); //pin 23 single ended
  pinMode(PIN_ADC2, INPUT); //pin 23 single ended

  adc->setReference(ADC_REF_1V2, ADC_0);
  adc->setReference(ADC_REF_1V2, ADC_1);
  adc->setSamplingSpeed(ADC_HIGH_SPEED);
}

static uint8_t adc_read()
{
  int ret = ADC_ERROR_VALUE;
  while (ret == ADC_ERROR_VALUE) {
    ret = adc->analogRead(A9, ADC_0);
  }
  return ret;
}

static uint32_t adc_rng_step() {
  uint8_t buffer[16];

  /* fill buffer */
  for (int i = 0; i < sizeof(buffer); i++) {
    buffer[i] = adc_read();
  }

  return CRC32.crc32(buffer, sizeof(buffer));
}
