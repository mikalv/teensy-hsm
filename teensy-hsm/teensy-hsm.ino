// Project : Teensy HSM
// Author  : Edi Permadi
// Repo    : https://github.com/edipermadi/teensy-hsm

// **************************************
// Changelog
// **************************************
// Oct 21, 2016 - Request payload buffer overflow checking
//              - Added random generation command (random taken from ADC noise)
//              - Added random reseed command (dummy response)
//
// Oct 20, 2016 - Fixed echo command
//              - Fixed information query command
//              - Rename YHSM_XX to THSM_XX
//
// Oct 19, 2016 - Added echo command
//              - Added information query command
//

// **************************************
// Board Setup
// **************************************
// Setup
// Board     : Teensy 3.1/3.2
// USB Type  : Serial
// CPU Speed : 72 MHz
// **************************************

//----------------------------------------
// Includes
//----------------------------------------
#include <ADC.h>

//----------------------------------------
// Hardare Configuration
//----------------------------------------
#define PIN_LED 13
#define PIN_ADC1 A9
#define PIN_ADC2 A9

//----------------------------------------
// Commands
//----------------------------------------
#define THSM_CMD_NULL                      0x00
#define THSM_CMD_AEAD_GENERATE             0x01
#define THSM_CMD_BUFFER_AEAD_GENERATE      0x02
#define THSM_CMD_RANDOM_AEAD_GENERATE      0x03
#define THSM_CMD_AEAD_DECRYPT_CMP          0x04
#define THSM_CMD_DB_YUBIKEY_AEAD_STORE     0x05
#define THSM_CMD_AEAD_YUBIKEY_OTP_DECODE   0x06
#define THSM_CMD_DB_OTP_VALIDATE           0x07
#define THSM_CMD_DB_YUBIKEY_AEAD_STORE2    0x08
#define THSM_CMD_AES_ECB_BLOCK_ENCRYPT     0x0d
#define THSM_CMD_AES_ECB_BLOCK_DECRYPT     0x0e
#define THSM_CMD_AES_ECB_BLOCK_DECRYPT_CMP 0x0f
#define THSM_CMD_HMAC_SHA1_GENERATE        0x10
#define THSM_CMD_TEMP_KEY_LOAD             0x11
#define THSM_CMD_BUFFER_LOAD               0x20
#define THSM_CMD_BUFFER_RANDOM_LOAD        0x21
#define THSM_CMD_NONCE_GET                 0x22
#define THSM_CMD_ECHO                      0x23
#define THSM_CMD_RANDOM_GENERATE           0x24
#define THSM_CMD_RANDOM_RESEED             0x25
#define THSM_CMD_SYSTEM_INFO_QUERY         0x26
#define THSM_CMD_HSM_UNLOCK                0x28
#define THSM_CMD_KEY_STORE_DECRYPT         0x29
#define THSM_CMD_MONITOR_EXIT              0x7f

//----------------------------------------
// Constants
//----------------------------------------
#define THSM_PUBLIC_ID_SIZE         6 // Size of public id for std OTP validation
#define THSM_OTP_SIZE              16 // Size of OTP
#define THSM_BLOCK_SIZE            16 // Size of block operations
#define THSM_MAX_KEY_SIZE          32 // Max size of CCMkey
#define THSM_DATA_BUF_SIZE         64 // Size of internal data buffer
#define THSM_AEAD_NONCE_SIZE        6 // Size of AEAD nonce (excluding size of key handle)
#define THSM_AEAD_MAC_SIZE          8 // Size of AEAD MAC field
#define THSM_CCM_CTR_SIZE           2 // Sizeof of AES CCM counter field
#define THSM_AEAD_MAX_SIZE       (THSM_DATA_BUF_SIZE + THSM_AEAD_MAC_SIZE) // Max size of an AEAD block
#define THSM_SHA1_HASH_SIZE        20 // 160-bit SHA1 hash size
#define THSM_CTR_DRBG_SEED_SIZE    32 // Size of CTR-DRBG entropy
#define THSM_MAX_PKT_SIZE        0x60 // Max size of a packet (excluding command byte)
#define THSM_PROTOCOL_VERSION       1 // Protocol version for this file

#define SYSTEM_ID_SIZE             12
#define THSM_FLAG_RESPONSE            0x80

#define STATE_WAIT_BCNT     0
#define STATE_WAIT_CMD      1
#define STATE_WAIT_PAYLOAD  2

// status code
#define THSM_STATUS_OK                0x80
#define THSM_STATUS_KEY_HANDLE_INVALID 0x81
#define THSM_STATUS_AEAD_INVALID       0x82
#define THSM_STATUS_OTP_INVALID        0x83
#define THSM_STATUS_OTP_REPLAY         0x84
#define THSM_STATUS_ID_DUPLICATE       0x85
#define THSM_STATUS_ID_NOT_FOUND       0x86
#define THSM_STATUS_DB_FULL            0x87
#define THSM_STATUS_MEMORY_ERROR       0x88
#define THSM_STATUS_FUNCTION_DISABLED  0x89
#define THSM_STATUS_KEY_STORAGE_LOCKED 0x8a
#define THSM_STATUS_MISMATCH           0x8b
#define THSM_STATUS_INVALID_PARAMETER  0x8c

// ------------------------------------
// Data Structures
// ------------------------------------
typedef struct
{
  uint8_t data_len;
  uint8_t data[THSM_MAX_PKT_SIZE - 1];
} THSM_ECHO_REQ;

typedef struct {
  uint8_t bytes_len;
} THSM_RANDOM_GENERATE_REQ;

typedef struct {
  uint8_t seed[THSM_CTR_DRBG_SEED_SIZE];
} THSM_RANDOM_RESEED_REQ;

typedef struct
{
  uint8_t data_len;
  uint8_t data[THSM_MAX_PKT_SIZE - 1];
} THSM_ECHO_RESP;

typedef struct
{
  uint8_t version_major;               // Major version #
  uint8_t version_minor;               // Minor version #
  uint8_t version_build;               // Build version #
  uint8_t protocol_version;            // Protocol version #
  uint8_t system_uid[SYSTEM_ID_SIZE];  // System unique identifier
} THSM_SYSTEM_INFO_RESP;

typedef struct {
  uint8_t bytes_len;
  uint8_t bytes[THSM_MAX_PKT_SIZE - 1];
} THSM_RANDOM_GENERATE_RESP;

typedef struct {
  uint8_t status;
} THSM_RANDOM_RESEED_RESP;

typedef union
{
  uint8_t                  raw[THSM_MAX_PKT_SIZE];
  THSM_ECHO_REQ            echo;
  THSM_RANDOM_GENERATE_REQ random_generate;
  THSM_RANDOM_RESEED_REQ   random_reseed;
} THSM_PAYLOAD_REQ;

typedef union
{
  uint8_t                   raw[THSM_MAX_PKT_SIZE];
  THSM_ECHO_RESP            echo;
  THSM_SYSTEM_INFO_RESP     system_info;
  THSM_RANDOM_GENERATE_RESP random_generate;
  THSM_RANDOM_RESEED_RESP   random_reseed;
} THSM_PAYLOAD_RESP;

typedef struct
{
  uint8_t bcnt;
  uint8_t cmd;
  THSM_PAYLOAD_REQ payload;
} THSM_PKT_REQ;

typedef struct
{
  uint8_t bcnt;
  uint8_t cmd;
  THSM_PAYLOAD_RESP payload;
} THSM_PKT_RESP;

// ------------------------------------
// Global Variables
// ------------------------------------

static THSM_PKT_REQ request;
static THSM_PKT_RESP response;
static ADC *adc = new ADC();

// ------------------------------------
// Functions
// ------------------------------------
void setup() {
  pinMode(PIN_LED, OUTPUT);
  pinMode(PIN_ADC1, INPUT); //pin 23 single ended
  pinMode(PIN_ADC2, INPUT); //pin 23 single ended
  adc->setReference(ADC_REF_1V2, ADC_0);
  adc->setReference(ADC_REF_1V2, ADC_1);
  adc->setSamplingSpeed(ADC_HIGH_SPEED);
  Serial.begin(9600);
  reset();
}

void loop() {
  uint8_t idx = 0;
  uint8_t remaining = 0;
  uint8_t state = STATE_WAIT_BCNT;
  uint8_t zero_ctr = 0;

  while (1) {
    if (Serial.available()) {
      // read character from USB
      int b = Serial.read();

      /* detect reset */
      zero_ctr = (b == 0) ? (zero_ctr + 1) : 0;
      if (zero_ctr == THSM_MAX_PKT_SIZE)
      {
        reset();
        zero_ctr = 0;
        state = STATE_WAIT_BCNT;
        continue;
      }

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
            if (remaining == 0)
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

          if (remaining == 0)
          {
            execute_cmd();
            reset();
            zero_ctr = 0;
            state = STATE_WAIT_BCNT;
          }
          break;
      }
    }
  }
}

static void reset()
{
  memset(&request, 0, sizeof(request));
  memset(&response, 0, sizeof(response));
}

static void execute_cmd()
{
  /* switch on LED */
  digitalWrite(PIN_LED, HIGH);

  switch (request.cmd)
  {
    case THSM_CMD_AEAD_GENERATE:
      break;
    case THSM_CMD_BUFFER_AEAD_GENERATE:
      break;
    case THSM_CMD_RANDOM_AEAD_GENERATE:
      break;
    case THSM_CMD_AEAD_DECRYPT_CMP:
      break;
    case THSM_CMD_DB_YUBIKEY_AEAD_STORE:
      break;
    case THSM_CMD_AEAD_YUBIKEY_OTP_DECODE:
      break;
    case THSM_CMD_DB_OTP_VALIDATE:
      break;
    case THSM_CMD_DB_YUBIKEY_AEAD_STORE2:
      break;
    case THSM_CMD_AES_ECB_BLOCK_ENCRYPT:
      break;
    case THSM_CMD_AES_ECB_BLOCK_DECRYPT:
      break;
    case THSM_CMD_AES_ECB_BLOCK_DECRYPT_CMP:
      break;
    case THSM_CMD_HMAC_SHA1_GENERATE:
      break;
    case THSM_CMD_TEMP_KEY_LOAD:
      break;
    case THSM_CMD_BUFFER_LOAD:
      break;
    case THSM_CMD_BUFFER_RANDOM_LOAD:
      break;
    case THSM_CMD_NONCE_GET:
      break;
    case THSM_CMD_ECHO:
      cmd_echo();
      break;
    case THSM_CMD_RANDOM_GENERATE:
      cmd_random_generate();
      break;
    case THSM_CMD_RANDOM_RESEED:
      cmd_random_reseed();
      break;
    case THSM_CMD_SYSTEM_INFO_QUERY:
      cmd_info_query();
      break;
    case THSM_CMD_HSM_UNLOCK:
      break;
    case THSM_CMD_KEY_STORE_DECRYPT:
      break;
    case THSM_CMD_MONITOR_EXIT:
      break;
  }

  /* switch on LED */
  digitalWrite(PIN_LED, LOW);
}

static void cmd_echo()
{
  /* cap echo data length to sizeof(THSM_ECHO_REQ::data) */
  uint8_t len = request.payload.echo.data_len;
  uint8_t max = sizeof(request.payload.echo.data);
  request.payload.echo.data_len = (len > max) ? max : len;
  request.bcnt = request.payload.echo.data_len + 2;

  memcpy(response.payload.echo.data, request.payload.echo.data, request.payload.echo.data_len);
  response.bcnt = request.bcnt;
  response.cmd = request.cmd | THSM_FLAG_RESPONSE;
  response.payload.echo.data_len = request.payload.echo.data_len;
  Serial.write((const char *)&response, (response.bcnt + 1));
}

static void cmd_info_query()
{
  response.bcnt = sizeof(response.payload.system_info) + 1;
  response.cmd = request.cmd | THSM_FLAG_RESPONSE;
  response.payload.system_info.version_major = 1;
  response.payload.system_info.version_minor = 0;
  response.payload.system_info.version_build = 4;
  response.payload.system_info.protocol_version = THSM_PROTOCOL_VERSION;
  memcpy(response.payload.system_info.system_uid, "Teensy HSM  ", SYSTEM_ID_SIZE);
  Serial.write((const char *)&response, response.bcnt + 1);
}

static void cmd_random_generate() {
  uint8_t len = request.payload.random_generate.bytes_len;
  uint8_t max = sizeof(response.payload.random_generate.bytes);
  request.payload.random_generate.bytes_len = (len > max) ? max : len;
  request.bcnt = request.payload.random_generate.bytes_len + 2;

  response.bcnt = request.bcnt;
  response.cmd = request.cmd | THSM_FLAG_RESPONSE;
  response.payload.random_generate.bytes_len = request.payload.random_generate.bytes_len;
  generate_random(response.payload.random_generate.bytes, response.payload.random_generate.bytes_len);
  Serial.write((const char *)&response, response.bcnt + 1);
}

static void cmd_random_reseed() {
  response.bcnt = 2;
  response.cmd = request.cmd | THSM_FLAG_RESPONSE;
  response.payload.random_reseed.status = THSM_STATUS_OK;
  Serial.write((const char *)&response, response.bcnt + 1);
}

static void generate_random(uint8_t *p_buffer, uint8_t len) {
  while (len > 0) {
    int val = adc->analogRead(A9, ADC_0);
    if (val == ADC_ERROR_VALUE) {
    } else {
      *p_buffer++ = val;
      --len;
    }
  }
}
