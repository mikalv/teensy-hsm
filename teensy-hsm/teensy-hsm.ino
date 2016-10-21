// Project : Teensy HSM
// Author  : Edi Permadi
// Repo    : https://github.com/edipermadi/teensy-hsm

// **************************************
// Changelog
// **************************************
// Oct 20, 2016 - Fixed Echo Command
//              - Fixed Info Query Command
//              - Rename YSM_XX to TSM_XX
//
// Oct 19, 2016 - Added Echo command
//              - Added Info Query Command
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
// Hardare Configuration
//----------------------------------------
#define PIN_LED 13

//----------------------------------------
// Commands
//----------------------------------------
#define TSM_NULL                      0x00
#define TSM_AEAD_GENERATE             0x01
#define TSM_BUFFER_AEAD_GENERATE      0x02
#define TSM_RANDOM_AEAD_GENERATE      0x03
#define TSM_AEAD_DECRYPT_CMP          0x04
#define TSM_DB_YUBIKEY_AEAD_STORE     0x05
#define TSM_AEAD_YUBIKEY_OTP_DECODE   0x06
#define TSM_DB_OTP_VALIDATE           0x07
#define TSM_DB_YUBIKEY_AEAD_STORE2    0x08
#define TSM_AES_ECB_BLOCK_ENCRYPT     0x0d
#define TSM_AES_ECB_BLOCK_DECRYPT     0x0e
#define TSM_AES_ECB_BLOCK_DECRYPT_CMP 0x0f
#define TSM_HMAC_SHA1_GENERATE        0x10
#define TSM_TEMP_KEY_LOAD             0x11
#define TSM_BUFFER_LOAD               0x20
#define TSM_BUFFER_RANDOM_LOAD        0x21
#define TSM_NONCE_GET                 0x22
#define TSM_ECHO                      0x23
#define TSM_RANDOM_GENERATE           0x24
#define TSM_RANDOM_RESEED             0x25
#define TSM_SYSTEM_INFO_QUERY         0x26
#define TSM_HSM_UNLOCK                0x28
#define TSM_KEY_STORE_DECRYPT         0x29
#define TSM_MONITOR_EXIT              0x7f

//----------------------------------------
// Constants
//----------------------------------------
#define TSM_PUBLIC_ID_SIZE         6 // Size of public id for std OTP validation
#define TSM_OTP_SIZE              16 // Size of OTP
#define TSM_BLOCK_SIZE            16 // Size of block operations
#define TSM_MAX_KEY_SIZE          32 // Max size of CCMkey
#define TSM_DATA_BUF_SIZE         64 // Size of internal data buffer
#define TSM_AEAD_NONCE_SIZE        6 // Size of AEAD nonce (excluding size of key handle)
#define TSM_AEAD_MAC_SIZE          8 // Size of AEAD MAC field
#define TSM_CCM_CTR_SIZE           2 // Sizeof of AES CCM counter field
#define TSM_AEAD_MAX_SIZE       (TSM_DATA_BUF_SIZE + TSM_AEAD_MAC_SIZE) // Max size of an AEAD block
#define TSM_SHA1_HASH_SIZE        20 // 160-bit SHA1 hash size
#define TSM_CTR_DRBG_SEED_SIZE    32 // Size of CTR-DRBG entropy
#define TSM_MAX_PKT_SIZE        0x60 // Max size of a packet (excluding command byte)
#define TSM_PROTOCOL_VERSION       1 // Protocol version for this file
#define SYSTEM_ID_SIZE            12
#define TSM_RESPONSE            0x80

#define STATE_WAIT_BCNT     0
#define STATE_WAIT_CMD      1
#define STATE_WAIT_PAYLOAD  2

// ------------------------------------
// Data Structures
// ------------------------------------
typedef struct
{
  uint8_t data_len;
  uint8_t data[TSM_MAX_PKT_SIZE - 1];
} TSM_ECHO_REQ;

typedef struct
{
  uint8_t data_len;
  uint8_t data[TSM_MAX_PKT_SIZE - 1];
} TSM_ECHO_RESP;

typedef struct
{
  uint8_t version_major;               // Major version #
  uint8_t version_minor;               // Minor version #
  uint8_t version_build;               // Build version #
  uint8_t protocol_version;            // Protocol version #
  uint8_t system_uid[SYSTEM_ID_SIZE];  // System unique identifier
} YHSM_SYSTEM_INFO_RESP;

typedef union
{
  uint8_t raw[TSM_MAX_PKT_SIZE];
  TSM_ECHO_REQ echo;
} TSM_PAYLOAD_REQ;

typedef union
{
  uint8_t raw[TSM_MAX_PKT_SIZE];
  TSM_ECHO_RESP echo;
  YHSM_SYSTEM_INFO_RESP system_info;
} TSM_PAYLOAD_RESP;

typedef struct
{
  uint8_t bcnt;
  uint8_t cmd;
  TSM_PAYLOAD_REQ payload;
} TSM_PKT_REQ;

typedef struct
{
  uint8_t bcnt;
  uint8_t cmd;
  TSM_PAYLOAD_RESP payload;
} TSM_PKT_RESP;

// ------------------------------------
// Global Variables
// ------------------------------------

static TSM_PKT_REQ request;
static TSM_PKT_RESP response;

// ------------------------------------
// Functions
// ------------------------------------
void setup() {
  pinMode(PIN_LED, OUTPUT);
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
      if (zero_ctr == TSM_MAX_PKT_SIZE)
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
          request.bcnt = (b > (TSM_MAX_PKT_SIZE + 1)) ? (TSM_MAX_PKT_SIZE + 1) : b;
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
            /* cap index by TSM_MAX_PKT_SIZE */
            if (idx < TSM_MAX_PKT_SIZE) {
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
    case TSM_AEAD_GENERATE:
      break;
    case TSM_BUFFER_AEAD_GENERATE:
      break;
    case TSM_RANDOM_AEAD_GENERATE:
      break;
    case TSM_AEAD_DECRYPT_CMP:
      break;
    case TSM_DB_YUBIKEY_AEAD_STORE:
      break;
    case TSM_AEAD_YUBIKEY_OTP_DECODE:
      break;
    case TSM_DB_OTP_VALIDATE:
      break;
    case TSM_DB_YUBIKEY_AEAD_STORE2:
      break;
    case TSM_AES_ECB_BLOCK_ENCRYPT:
      break;
    case TSM_AES_ECB_BLOCK_DECRYPT:
      break;
    case TSM_AES_ECB_BLOCK_DECRYPT_CMP:
      break;
    case TSM_HMAC_SHA1_GENERATE:
      break;
    case TSM_TEMP_KEY_LOAD:
      break;
    case TSM_BUFFER_LOAD:
      break;
    case TSM_BUFFER_RANDOM_LOAD:
      break;
    case TSM_NONCE_GET:
      break;
    case TSM_ECHO:
      cmd_echo();
      break;
    case TSM_RANDOM_GENERATE:
      break;
    case TSM_RANDOM_RESEED:
      break;
    case TSM_SYSTEM_INFO_QUERY:
      cmd_info_query();
      break;
    case TSM_HSM_UNLOCK:
      break;
    case TSM_KEY_STORE_DECRYPT:
      break;
    case TSM_MONITOR_EXIT:
      break;
  }

  /* switch on LED */
  digitalWrite(PIN_LED, LOW);
}

static void cmd_echo()
{
  /* cap echo data length to sizeof(TSM_ECHO_REQ::data) */
  uint8_t len = request.payload.echo.data_len;
  uint8_t max = sizeof(request.payload.echo.data);
  request.payload.echo.data_len = (len > max) ? max : len;

  memcpy(response.payload.echo.data, request.payload.echo.data, request.payload.echo.data_len);
  response.bcnt = request.payload.echo.data_len + 2;
  response.cmd = request.cmd | TSM_RESPONSE;
  response.payload.echo.data_len = request.payload.echo.data_len;
  Serial.write((const char *)&response, (response.bcnt + 1));
}

static void cmd_info_query()
{
  response.bcnt = sizeof(response.payload.system_info) + 1;
  response.cmd = request.cmd | TSM_RESPONSE;
  response.payload.system_info.version_major = 1;
  response.payload.system_info.version_minor = 0;
  response.payload.system_info.version_build = 4;
  response.payload.system_info.protocol_version = TSM_PROTOCOL_VERSION;
  memcpy(response.payload.system_info.system_uid, "Teensy HSM  ", SYSTEM_ID_SIZE);
  Serial.write((const char *)&response, response.bcnt + 1);
}
