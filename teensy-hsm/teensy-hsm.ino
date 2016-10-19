// Project : Teensy HSM
// Author  : Edi Permadi
// Repo    : https://github.com/edipermadi/teensy-hsm

// **************************************
// Changelog
// **************************************
// Oct 19, 2016 - Added Echo command
//              - Added Info Query Command

// **************************************
// Board Setup
// **************************************
// Setup
// Board     : Teensy 3.1/3.2
// USB Type  : Serial
// CPU Speed : 72 MHz
// **************************************


//----------------------------------------
// Commands
//----------------------------------------
#define YSM_NULL                      0x00
#define YSM_AEAD_GENERATE             0x01
#define YSM_BUFFER_AEAD_GENERATE      0x02
#define YSM_RANDOM_AEAD_GENERATE      0x03
#define YSM_AEAD_DECRYPT_CMP          0x04
#define YSM_DB_YUBIKEY_AEAD_STORE     0x05
#define YSM_AEAD_YUBIKEY_OTP_DECODE   0x06
#define YSM_DB_OTP_VALIDATE           0x07
#define YSM_DB_YUBIKEY_AEAD_STORE2    0x08
#define YSM_AES_ECB_BLOCK_ENCRYPT     0x0d
#define YSM_AES_ECB_BLOCK_DECRYPT     0x0e
#define YSM_AES_ECB_BLOCK_DECRYPT_CMP 0x0f
#define YSM_HMAC_SHA1_GENERATE        0x10
#define YSM_TEMP_KEY_LOAD             0x11
#define YSM_BUFFER_LOAD               0x20
#define YSM_BUFFER_RANDOM_LOAD        0x21
#define YSM_NONCE_GET                 0x22
#define YSM_ECHO                      0x23
#define YSM_RANDOM_GENERATE           0x24
#define YSM_RANDOM_RESEED             0x25
#define YSM_SYSTEM_INFO_QUERY         0x26
#define YSM_HSM_UNLOCK                0x28
#define YSM_KEY_STORE_DECRYPT         0x29
#define YSM_MONITOR_EXIT              0x7f

//----------------------------------------
// Constants
//----------------------------------------
#define YSM_PUBLIC_ID_SIZE         6 // Size of public id for std OTP validation
#define YSM_OTP_SIZE              16 // Size of OTP
#define YSM_BLOCK_SIZE            16 // Size of block operations
#define YSM_MAX_KEY_SIZE          32 // Max size of CCMkey
#define YSM_DATA_BUF_SIZE         64 // Size of internal data buffer
#define YSM_AEAD_NONCE_SIZE        6 // Size of AEAD nonce (excluding size of key handle)
#define YSM_AEAD_MAC_SIZE          8 // Size of AEAD MAC field
#define YSM_CCM_CTR_SIZE           2 // Sizeof of AES CCM counter field
#define YSM_AEAD_MAX_SIZE       (YSM_DATA_BUF_SIZE + YSM_AEAD_MAC_SIZE) // Max size of an AEAD block
#define YSM_SHA1_HASH_SIZE        20 // 160-bit SHA1 hash size
#define YSM_CTR_DRBG_SEED_SIZE    32 // Size of CTR-DRBG entropy
#define YSM_MAX_PKT_SIZE        0x60 // Max size of a packet (excluding command byte)
#define YSM_PROTOCOL_VERSION       1 // Protocol version for this file
#define SYSTEM_ID_SIZE            12

#define STATE_WAIT_BCNT     0
#define STATE_WAIT_CMD      1
#define STATE_WAIT_PAYLOAD  2

// ------------------------------------
// Data Structures
// ------------------------------------
typedef struct {
  uint8_t bcnt;
  uint8_t cmd;
  uint8_t payload[YSM_MAX_PKT_SIZE];
} YSM_PKT;

typedef struct {
  uint8_t data_len;
  uint8_t data[YSM_MAX_PKT_SIZE - 1];
} YSM_ECHO_REQ;

typedef struct {
  uint8_t data_len;
  uint8_t data[YSM_MAX_PKT_SIZE - 1];
} YSM_ECHO_RESP;

typedef struct {
  uint8_t version_major;               // Major version #
  uint8_t version_minor;               // Minor version #
  uint8_t version_build;               // Build version #
  uint8_t protocol_version;            // Protocol version #
  uint8_t system_uid[SYSTEM_ID_SIZE];  // System unique identifier
} YHSM_SYSTEM_INFO_RESP;

// ------------------------------------
// Global Variables
// ------------------------------------
static YSM_PKT buffer_in;
static YSM_PKT buffer_out;
static uint32_t payload_idx = 0;
static uint32_t remaining = 0;
static uint32_t state = STATE_WAIT_BCNT;
static uint32_t zero_ctr = 0;

// ------------------------------------
// Functions
// ------------------------------------
void setup() {
  pinMode(13, OUTPUT);
  Serial.begin(9600);
  reset();
}

void loop() {
  while (1) {
    if (Serial.available()) {
      // read character from USB
      int b = Serial.read();

      // update zero counter
      zero_ctr = (b == 0) ? (zero_ctr + 1) : 0;
      if (zero_ctr == (YSM_MAX_PKT_SIZE - 1)) {
        reset();
        continue;
      }

      // dispatch state
      switch (state)
      {
        case STATE_WAIT_BCNT:
          if (b != 0) {
            buffer_in.bcnt = b;
            remaining = b;
            state = STATE_WAIT_CMD;
          }
          break;

        case STATE_WAIT_CMD:
          if (b == 0) {
            state = STATE_WAIT_CMD;
          } else if (remaining-- > 0) {
            buffer_in.cmd = b;
            if (remaining == 0) {
              execute_cmd();
              state = STATE_WAIT_BCNT;
            } else {
              state = STATE_WAIT_PAYLOAD;
            }
          } else {
            state = STATE_WAIT_BCNT;
          }
          break;

        case STATE_WAIT_PAYLOAD:
          if (remaining-- > 0) {
            buffer_in.payload[payload_idx++] = b;
          }

          if (remaining == 0) {
            execute_cmd();
          }
          break;
      }
    }
  }
}

static void reset() {
  memset(&buffer_in, 0, sizeof(buffer_in));
  memset(&buffer_out, 0, sizeof(buffer_out));
  payload_idx = 0;
  remaining = 0;
  state = STATE_WAIT_BCNT;
  zero_ctr = 0;
}

static void execute_cmd() {
  digitalWrite(13, HIGH);
  switch (buffer_in.cmd) {
    case YSM_AEAD_GENERATE: break;
    case YSM_BUFFER_AEAD_GENERATE: break;
    case YSM_RANDOM_AEAD_GENERATE: break;
    case YSM_AEAD_DECRYPT_CMP: break;
    case YSM_DB_YUBIKEY_AEAD_STORE: break;
    case YSM_AEAD_YUBIKEY_OTP_DECODE: break;
    case YSM_DB_OTP_VALIDATE: break;
    case YSM_DB_YUBIKEY_AEAD_STORE2: break;
    case YSM_AES_ECB_BLOCK_ENCRYPT: break;
    case YSM_AES_ECB_BLOCK_DECRYPT: break;
    case YSM_AES_ECB_BLOCK_DECRYPT_CMP: break;
    case YSM_HMAC_SHA1_GENERATE: break;
    case YSM_TEMP_KEY_LOAD: break;
    case YSM_BUFFER_LOAD: break;
    case YSM_BUFFER_RANDOM_LOAD: break;
    case YSM_NONCE_GET: break;
    case YSM_ECHO:
      cmd_echo();
      break;
    case YSM_RANDOM_GENERATE: break;
    case YSM_RANDOM_RESEED: break;
    case YSM_SYSTEM_INFO_QUERY:
      cmd_info_query();
      break;
    case YSM_HSM_UNLOCK: break;
    case YSM_KEY_STORE_DECRYPT: break;
    case YSM_MONITOR_EXIT: break;
  }

  delay(50);
  digitalWrite(13, LOW);

}

static void cmd_echo() {
  if (buffer_in.bcnt == (buffer_in.payload[0] + 2)) {
    uint32_t len = buffer_in.bcnt + 1;
    memcpy(&buffer_out, &buffer_in, len);
    Serial.write((const char *)&buffer_out, len);
  } else {
    // invalid length
    reset();
  }
}

static void cmd_info_query() {
  YHSM_SYSTEM_INFO_RESP rsp;
  rsp.version_major = 1;
  rsp.version_minor = 0;
  rsp.version_build = 1;
  rsp.protocol_version = YSM_PROTOCOL_VERSION;
  memcpy(rsp.system_uid, "Teensy HSM  ", SYSTEM_ID_SIZE);
  memcpy(buffer_out.payload, &rsp, sizeof(rsp));
  buffer_out.bcnt = sizeof(rsp) + 1;
  buffer_out.cmd = YSM_SYSTEM_INFO_QUERY;
  Serial.write((const char *)&buffer_out, buffer_out.bcnt + 1);
}
