
//--------------------------------------------------------------------------------------------------
// PRNG
//--------------------------------------------------------------------------------------------------
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

static void adc_rng_read(uint8_t *p_buffer, uint32_t len)
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
