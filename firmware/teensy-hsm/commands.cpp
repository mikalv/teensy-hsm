#include "commands.h"
#include "macros.h"
#include "aes.h"
#include "aes-ccm.h"
#include "error.h"
#include "util.h"

//------------------------------------------------------------------------------
// Command Identifier
//------------------------------------------------------------------------------
#define THSM_CMD_NULL                       0x00
#define THSM_CMD_AEAD_GENERATE              0x01
#define THSM_CMD_BUFFER_AEAD_GENERATE       0x02
#define THSM_CMD_RANDOM_AEAD_GENERATE       0x03
#define THSM_CMD_AEAD_DECRYPT_CMP           0x04
#define THSM_CMD_DB_AEAD_STORE              0x05
#define THSM_CMD_AEAD_OTP_DECODE            0x06
#define THSM_CMD_DB_OTP_VALIDATE            0x07
#define THSM_CMD_DB_AEAD_STORE2             0x08
#define THSM_CMD_AES_ECB_BLOCK_ENCRYPT      0x0d
#define THSM_CMD_AES_ECB_BLOCK_DECRYPT      0x0e
#define THSM_CMD_AES_ECB_BLOCK_DECRYPT_CMP  0x0f
#define THSM_CMD_HMAC_SHA1_GENERATE         0x10
#define THSM_CMD_TEMP_KEY_LOAD              0x11
#define THSM_CMD_BUFFER_LOAD                0x20
#define THSM_CMD_BUFFER_RANDOM_LOAD         0x21
#define THSM_CMD_NONCE_GET                  0x22
#define THSM_CMD_ECHO                       0x23
#define THSM_CMD_RANDOM_GENERATE            0x24
#define THSM_CMD_RANDOM_RESEED              0x25
#define THSM_CMD_SYSTEM_INFO_QUERY          0x26
#define THSM_CMD_HSM_UNLOCK                 0x28
#define THSM_CMD_KEY_STORE_DECRYPT          0x29
#define THSM_CMD_MONITOR_EXIT               0x7f

//======================================================================================================================
// STRUCTURES
//======================================================================================================================
typedef struct
{
    uint8_t nonce[AES_CCM_NONCE_SIZE_BYTES];
    uint8_t key_handle[sizeof(uint32_t)];
    uint8_t data_len;
    uint8_t data[THSM_DATA_BUF_SIZE];
} THSM_AEAD_GENERATE_REQ;

typedef struct
{
    uint8_t nonce[AES_CCM_NONCE_SIZE_BYTES];
    uint8_t key_handle[sizeof(uint32_t)];
    uint8_t status;
    uint8_t data_len;
    uint8_t data[AES_CCM_MAX_AEAD_LENGTH_BYTES];
} THSM_AEAD_GENERATE_RESP;

typedef struct
{
    uint8_t nonce[THSM_AEAD_NONCE_SIZE];
    uint8_t key_handle[THSM_KEY_HANDLE_SIZE];
} THSM_BUFFER_AEAD_GENERATE_REQ;

typedef struct
{
    uint8_t nonce[THSM_AEAD_NONCE_SIZE];
    uint8_t key_handle[THSM_KEY_HANDLE_SIZE];
    uint8_t status;
    uint8_t data_len;
    uint8_t data[THSM_AEAD_MAX_SIZE];
} THSM_BUFFER_AEAD_GENERATE_RESP;

typedef struct
{
    uint8_t nonce[THSM_AEAD_NONCE_SIZE];
    uint8_t key_handle[THSM_KEY_HANDLE_SIZE];
    uint8_t random_len;
} THSM_RANDOM_AEAD_GENERATE_REQ;

typedef struct
{
    uint8_t nonce[THSM_AEAD_NONCE_SIZE];
    uint8_t key_handle[THSM_KEY_HANDLE_SIZE];
    uint8_t status;
    uint8_t data_len;
    uint8_t data[THSM_AEAD_MAX_SIZE];
} THSM_RANDOM_AEAD_GENERATE_RESP;

typedef struct
{
    uint8_t nonce[THSM_AEAD_NONCE_SIZE];
    uint8_t key_handle[THSM_KEY_HANDLE_SIZE];
    uint8_t data_len;
    uint8_t data[THSM_MAX_PKT_SIZE - 0x10];
} THSM_AEAD_DECRYPT_CMP_REQ;

typedef struct
{
    uint8_t nonce[THSM_AEAD_NONCE_SIZE];
    uint8_t key_handle[THSM_KEY_HANDLE_SIZE];
    uint8_t status;
} THSM_AEAD_DECRYPT_CMP_RESP;

typedef struct
{
    uint8_t public_id[THSM_PUBLIC_ID_SIZE];
    uint8_t key_handle[THSM_KEY_HANDLE_SIZE];
    uint8_t aead[THSM_AEAD_SIZE]; // key || nonce || mac
} THSM_DB_AEAD_STORE_REQ;

typedef struct
{
    uint8_t public_id[THSM_PUBLIC_ID_SIZE];
    uint8_t key_handle[THSM_KEY_HANDLE_SIZE];
    uint8_t status;
} THSM_DB_AEAD_STORE_RESP;

typedef struct
{
    uint8_t public_id[THSM_PUBLIC_ID_SIZE];
    uint8_t key_handle[THSM_KEY_HANDLE_SIZE];
    uint8_t otp[THSM_OTP_SIZE];
    uint8_t aead[THSM_AEAD_SIZE];
} THSM_AEAD_OTP_DECODE_REQ;

typedef struct
{
    uint8_t public_id[THSM_PUBLIC_ID_SIZE];
    uint8_t key_handle[THSM_KEY_HANDLE_SIZE];
    uint8_t counter_timestamp[THSM_AEAD_NONCE_SIZE]; // uint16_use_ctr | uint8_session_ctr | uint24_timestamp
    uint8_t status;
} THSM_AEAD_OTP_DECODE_RESP;

typedef struct
{
    uint8_t public_id[THSM_PUBLIC_ID_SIZE];
    uint8_t otp[THSM_OTP_SIZE];
} THSM_DB_OTP_VALIDATE_REQ;

typedef struct
{
    uint8_t public_id[THSM_PUBLIC_ID_SIZE];
    uint8_t counter_timestamp[THSM_AEAD_NONCE_SIZE]; // uint16_use_ctr | uint8_session_ctr | uint24_timestamp
    uint8_t status;
} THSM_DB_OTP_VALIDATE_RESP;

typedef struct
{
    uint8_t public_id[THSM_PUBLIC_ID_SIZE];
    uint8_t key_handle[THSM_KEY_HANDLE_SIZE];
    uint8_t aead[THSM_AEAD_SIZE]; // key || nonce || mac
    uint8_t nonce[THSM_AEAD_NONCE_SIZE];
} THSM_DB_AEAD_STORE2_REQ;

typedef struct
{
    uint8_t public_id[THSM_PUBLIC_ID_SIZE];
    uint8_t key_handle[THSM_KEY_HANDLE_SIZE];
    uint8_t status;
} THSM_DB_AEAD_STORE2_RESP;

typedef struct
{
    uint8_t key_handle[THSM_KEY_HANDLE_SIZE];
    uint8_t plaintext[THSM_BLOCK_SIZE];
} THSM_AES_ECB_BLOCK_ENCRYPT_REQ;

typedef struct
{
    uint8_t key_handle[THSM_KEY_HANDLE_SIZE];
    uint8_t ciphertext[THSM_BLOCK_SIZE];
    uint8_t status;
} THSM_AES_ECB_BLOCK_ENCRYPT_RESP;

typedef struct
{
    uint8_t key_handle[THSM_KEY_HANDLE_SIZE];
    uint8_t ciphertext[THSM_BLOCK_SIZE];
} THSM_AES_ECB_BLOCK_DECRYPT_REQ;

typedef struct
{
    uint8_t key_handle[THSM_KEY_HANDLE_SIZE];
    uint8_t plaintext[THSM_BLOCK_SIZE];
    uint8_t status;
} THSM_AES_ECB_BLOCK_DECRYPT_RESP;

typedef struct
{
    uint8_t key_handle[THSM_KEY_HANDLE_SIZE];
    uint8_t status;
} THSM_AES_ECB_BLOCK_DECRYPT_CMP_RESP;

typedef struct
{
    uint8_t key_handle[THSM_KEY_HANDLE_SIZE];
    uint8_t ciphertext[THSM_BLOCK_SIZE];
    uint8_t plaintext[THSM_BLOCK_SIZE];
} THSM_AES_ECB_BLOCK_DECRYPT_CMP_REQ;

typedef struct
{
    uint8_t key_handle[THSM_KEY_HANDLE_SIZE];
    uint8_t flags;
    uint8_t data_len;
    uint8_t data[THSM_MAX_PKT_SIZE - 6];
} THSM_HMAC_SHA1_GENERATE_REQ;

typedef struct
{
    uint8_t key_handle[THSM_KEY_HANDLE_SIZE];
    uint8_t status;
    uint8_t data_len;
    uint8_t data[THSM_SHA1_HASH_SIZE];
} THSM_HMAC_SHA1_GENERATE_RESP;

typedef struct
{
    uint8_t nonce[THSM_AEAD_NONCE_SIZE];
    uint8_t key_handle[THSM_KEY_HANDLE_SIZE];
    uint8_t data_len;
    uint8_t data[THSM_MAX_KEY_SIZE + sizeof(uint32_t) + THSM_AEAD_MAC_SIZE];
} THSM_TEMP_KEY_LOAD_REQ;

typedef struct
{
    uint8_t nonce[THSM_AEAD_NONCE_SIZE];
    uint8_t key_handle[THSM_KEY_HANDLE_SIZE];
    uint8_t status;
} THSM_TEMP_KEY_LOAD_RESP;

typedef struct
{
    uint8_t offset;
    uint8_t data_len;
    uint8_t data[THSM_DATA_BUF_SIZE];
} THSM_BUFFER_LOAD_REQ;

typedef struct
{
    uint8_t length;
} THSM_BUFFER_LOAD_RESP;

typedef struct
{
    uint8_t offset;
    uint8_t length;
} THSM_BUFFER_RANDOM_LOAD_REQ;

typedef struct
{
    uint8_t length;
} THSM_BUFFER_RANDOM_LOAD_RESP;

typedef struct
{
    uint8_t post_inc[sizeof(uint16_t)];
} THSM_NONCE_GET_REQ;

typedef struct
{
    uint8_t status;
    uint8_t nonce[THSM_AEAD_NONCE_SIZE];
} THSM_NONCE_GET_RESP;

typedef struct
{
    uint8_t data_len;
    uint8_t data[THSM_MAX_PKT_SIZE - 1];
} THSM_ECHO_REQ;

typedef struct
{
    uint8_t data_len;
    uint8_t data[THSM_MAX_PKT_SIZE - 1];
} THSM_ECHO_RESP;

typedef struct
{
    uint8_t bytes_len;
} THSM_RANDOM_GENERATE_REQ;

typedef struct
{
    uint8_t bytes_len;
    uint8_t bytes[THSM_MAX_PKT_SIZE - 1];
} THSM_RANDOM_GENERATE_RESP;

typedef struct
{
    uint8_t seed[AES_DRBG_SEED_SIZE_BYTES];
} THSM_RANDOM_RESEED_REQ;

typedef struct
{
    uint8_t status;
} THSM_RANDOM_RESEED_RESP;

typedef struct
{
    uint8_t version_major;             // Major version number
    uint8_t version_minor;             // Minor version number
    uint8_t version_build;             // Build version number
    uint8_t protocol_version;          // Protocol version number
    uint8_t system_uid[THSM_SYSTEM_ID_SIZE]; // System unique identifier
} THSM_SYSTEM_INFO_QUERY_RESP;

typedef struct
{
    uint8_t public_id[THSM_PUBLIC_ID_SIZE];
    uint8_t otp[THSM_OTP_SIZE];
} THSM_HSM_UNLOCK_REQ;

typedef struct
{
    uint8_t status;
} THSM_HSM_UNLOCK_RESP;

typedef struct
{
    uint8_t key[THSM_MAX_KEY_SIZE];
} THSM_KEY_STORE_DECRYPT_REQ;

typedef struct
{
    uint8_t status;
} THSM_KEY_STORE_DECRYPT_RESP;

Commands::Commands()
{
    flags = Flags();
}

int32_t Commands::process(uint8_t cmd, packet_t &response, const packet_t &request)
{
    switch (cmd)
    {
    case THSM_CMD_NULL:
        return null(response, request);
    case THSM_CMD_AEAD_GENERATE:
        return aead_generate(response, request);
    case THSM_CMD_BUFFER_AEAD_GENERATE:
        return buffer_aead_generate(response, request);
    case THSM_CMD_RANDOM_AEAD_GENERATE:
        return random_aead_generate(response, request);
    case THSM_CMD_AEAD_DECRYPT_CMP:
        return aead_decrypt_cmp(response, request);
    case THSM_CMD_DB_AEAD_STORE:
        return db_aead_store(response, request);
    case THSM_CMD_AEAD_OTP_DECODE:
        return aead_otp_decode(response, request);
    case THSM_CMD_DB_OTP_VALIDATE:
        return db_otp_validate(response, request);
    case THSM_CMD_DB_AEAD_STORE2:
        return db_aead_store2(response, request);
    case THSM_CMD_AES_ECB_BLOCK_ENCRYPT:
        return aes_ecb_block_encrypt(response, request);
    case THSM_CMD_AES_ECB_BLOCK_DECRYPT:
        return aes_ecb_block_decrypt(response, request);
    case THSM_CMD_AES_ECB_BLOCK_DECRYPT_CMP:
        return aes_ecb_block_decrypt_cmp(response, request);
    case THSM_CMD_HMAC_SHA1_GENERATE:
        return hmac_sha1_generate(response, request);
    case THSM_CMD_TEMP_KEY_LOAD:
        return temp_key_load(response, request);
    case THSM_CMD_BUFFER_LOAD:
        return buffer_load(response, request);
    case THSM_CMD_BUFFER_RANDOM_LOAD:
        return buffer_random_load(response, request);
    case THSM_CMD_NONCE_GET:
        return nonce_get(response, request);
    case THSM_CMD_ECHO:
        return echo(response, request);
    case THSM_CMD_RANDOM_GENERATE:
        return random_generate(response, request);
    case THSM_CMD_RANDOM_RESEED:
        return random_reseed(response, request);
    case THSM_CMD_SYSTEM_INFO_QUERY:
        return system_info_query(response, request);
    case THSM_CMD_HSM_UNLOCK:
        return hsm_unlock(response, request);
    case THSM_CMD_KEY_STORE_DECRYPT:
        return key_store_decrypt(response, request);
    case THSM_CMD_MONITOR_EXIT:
        return monitor_exit(response, request);
    default:
        return ERROR_CODE_UNKNOWN_COMMAND;
    }
}

int32_t Commands::null(packet_t &response, const packet_t &request)
{
    return 0;
}

int32_t Commands::aead_generate(packet_t &output, const packet_t &input)
{
    if (input.length < 11)
    {
        return ERROR_CODE_INVALID_REQUEST;
    }

    THSM_AEAD_GENERATE_REQ request;
    THSM_AEAD_GENERATE_RESP response;
    MEMCLR(request);
    MEMCLR(response);
    memcpy(&request, input.bytes, MIN(sizeof(request), input.length));

    if (input.length < (request.data_len + 11))
    {
        return ERROR_CODE_INVALID_REQUEST;
    }

    /* get key handle, status and length */
    uint32_t key_handle = READ32(request.key_handle);

    /* get key */
    key_info_t key_info;
    int ret = storage.get_key(key_info, key_handle);
    if (ret < 0)
    {
        return ret;
    }

    /* generate nonce if it is null */
    aes_ccm_nonce_t nonce;
    if (Util::is_empty(request.nonce, sizeof(request.nonce)))
    {
        aes_state_t random;
        drbg.generate(random);
        memcpy(nonce.bytes, random.bytes, sizeof(nonce.bytes));
    }
    else
    {
        memcpy(nonce.bytes, request.nonce, sizeof(nonce.bytes));
    }

    aes_state_t key, pt, ct;
    aes_ccm_mac_t mac;
    AES::state_fill(key, key_info.bytes);

    AESCCM aes = AESCCM();
    aes.init(key, key_handle, nonce, request.data_len);

    uint32_t length = request.data_len;
    uint8_t *src_data = request.data;
    uint8_t *dst_data = response.data;
    while (length)
    {
        MEMCLR(pt);
        uint32_t step = MIN(length, sizeof(pt.bytes));
        memcpy(pt.bytes, src_data, step);

        aes.encrypt_update(ct, pt);
        memcpy(dst_data, ct.bytes, step);

        src_data += step;
        dst_data += step;
        length -= step;
    }

    aes.encrypt_final(mac);

    /* copy key handle and nonce */
    response.status = THSM_STATUS_OK;
    response.data_len = request.data_len + sizeof(mac.bytes);
    memcpy(response.key_handle, request.key_handle, sizeof(request.key_handle));
    memcpy(response.nonce, request.nonce, sizeof(request.nonce));
    memcpy(dst_data, mac.bytes, sizeof(mac.bytes));

    return response.data_len + 12;
}

int32_t Commands::buffer_aead_generate(packet_t &response, const packet_t &request)
{
    /* FIXME add implementation */
}

int32_t Commands::random_aead_generate(packet_t &response, const packet_t &request)
{
    /* FIXME add implementation */
}

int32_t Commands::aead_decrypt_cmp(packet_t &response, const packet_t &request)
{
    /* FIXME add implementation */
}

int32_t Commands::db_aead_store(packet_t &response, const packet_t &request)
{
    /* FIXME add implementation */
}

int32_t Commands::aead_otp_decode(packet_t &response, const packet_t &request)
{
    /* FIXME add implementation */
}

int32_t Commands::db_otp_validate(packet_t &response, const packet_t &request)
{
    /* FIXME add implementation */
}

int32_t Commands::db_aead_store2(packet_t &response, const packet_t &request)
{
    /* FIXME add implementation */
}

int32_t Commands::aes_ecb_block_encrypt(packet_t &response, const packet_t &request)
{
    /* FIXME add implementation */
}

int32_t Commands::aes_ecb_block_decrypt(packet_t &response, const packet_t &request)
{
    /* FIXME add implementation */
}

int32_t Commands::aes_ecb_block_decrypt_cmp(packet_t &response, const packet_t &request)
{
    /* FIXME add implementation */
}

int32_t Commands::hmac_sha1_generate(packet_t &response, const packet_t &request)
{
    /* FIXME add implementation */
}

int32_t Commands::temp_key_load(packet_t &response, const packet_t &request)
{
    /* FIXME add implementation */
}

int32_t Commands::buffer_load(packet_t &response, const packet_t &request)
{
    /* FIXME add implementation */
}

int32_t Commands::buffer_random_load(packet_t &response, const packet_t &request)
{
    /* FIXME add implementation */
}

int32_t Commands::nonce_get(packet_t &response, const packet_t &request)
{
    /* FIXME add implementation */
}

int32_t Commands::echo(packet_t &response, const packet_t &request)
{
    /* FIXME add implementation */
}

int32_t Commands::random_generate(packet_t &output, const packet_t &input)
{
    THSM_RANDOM_GENERATE_REQ request;
    THSM_RANDOM_GENERATE_RESP response;

    if (input.length < sizeof(request))
    {
        return ERROR_CODE_INVALID_REQUEST;
    }

    /* initialize buffer */
    memcpy(&request, input.bytes, sizeof(request));
    MEMCLR(response);

    /* truncate requested length */
    uint8_t *ptr = response.bytes;
    uint8_t length = MIN(request.bytes_len, sizeof(response.bytes));
    response.bytes_len = length;

    while (length)
    {
        aes_state_t random;
        int32_t ret = drbg.generate(random);
        if (ret < 0)
        {
            return ret;
        }

        uint32_t step = MIN(length, sizeof(random.bytes));
        memcpy(ptr, random.bytes, step);

        ptr += step;
        length -= step;
    }

    uint32_t output_length = (response.bytes_len + 1);
    output.length = output_length;
    memcpy(output.bytes, &response, output_length);

    return ERROR_CODE_NONE;
}

int32_t Commands::random_reseed(packet_t &response, const packet_t &request)
{
    /* FIXME add implementation */
}

int32_t Commands::system_info_query(packet_t &response, const packet_t &request)
{
    /* FIXME add implementation */
}

int32_t Commands::hsm_unlock(packet_t &response, const packet_t &request)
{
    /* FIXME add implementation */
}

int32_t Commands::key_store_decrypt(packet_t &response, const packet_t &request)
{
    /* FIXME add implementation */
}

int32_t Commands::monitor_exit(packet_t &response, const packet_t &request)
{
    /* FIXME add implementation */
}

//--------------------------------------------------------------------------------------------------
// Command Handlers
//--------------------------------------------------------------------------------------------------
static void cmd_echo()
{
    /* cap echo data length to sizeof(THSM_ECHO_REQ::data) */
    uint8_t curr_length = request.payload.echo.data_len;
    uint8_t max_length = sizeof(request.payload.echo.data);
    uint8_t length = (curr_length > max_length) ? max_length : curr_length;

    uint8_t *dst_data = response.payload.echo.data;
    uint8_t *src_data = request.payload.echo.data;

    /* copy data */
    memcpy(dst_data, src_data, length);
    response.bcnt = length + 2;
    response.payload.echo.data_len = request.payload.echo.data_len;
}

static void cmd_info_query()
{
    response.bcnt = sizeof(response.payload.system_info) + 1;
    response.payload.system_info.version_major = 1;
    response.payload.system_info.version_minor = 0;
    response.payload.system_info.version_build = 4;
    response.payload.system_info.protocol_version = THSM_PROTOCOL_VERSION;
    memcpy(response.payload.system_info.system_uid, "Teensy HSM  ", THSM_SYSTEM_ID_SIZE);
}

static void cmd_random_reseed()
{
    response.bcnt = 2;
    response.payload.random_reseed.status = THSM_STATUS_OK;

    /* reseed drbg */
    drbg_reseed(request.payload.random_reseed.seed);
}

static void cmd_hmac_sha1_generate()
{
    uint8_t key[THSM_KEY_SIZE];
    uint32_t flags;

    uint8_t *src_key = request.payload.hmac_sha1_generate.key_handle;
    uint8_t *dst_key = response.payload.hmac_sha1_generate.key_handle;
    uint8_t *src_data = request.payload.hmac_sha1_generate.data;
    uint8_t *dst_data = response.payload.hmac_sha1_generate.data;

    /* set common response */
    response.bcnt = (sizeof(response.payload.hmac_sha1_generate) - sizeof(response.payload.hmac_sha1_generate.data)) + 1;
    response.payload.hmac_sha1_generate.data_len = 0;
    response.payload.hmac_sha1_generate.status = THSM_STATUS_OK;

    /* copy key handle */
    memcpy(dst_key, src_key, THSM_KEY_HANDLE_SIZE);

    /* check given key handle */
    uint8_t status = THSM_STATUS_OK;
    uint16_t length = request.payload.hmac_sha1_generate.data_len;
    uint32_t key_handle = read_uint32(src_key);
    if (flags_is_secret_locked())
    {
        response.payload.hmac_sha1_generate.status = THSM_STATUS_KEY_STORAGE_LOCKED;
    }
    else if (request.bcnt > (sizeof(request.payload.hmac_sha1_generate) + 1))
    {
        response.payload.hmac_sha1_generate.status = THSM_STATUS_INVALID_PARAMETER;
    }
    else if ((length < 1) || (length > sizeof(request.payload.hmac_sha1_generate.data)))
    {
        response.payload.hmac_sha1_generate.status = THSM_STATUS_INVALID_PARAMETER;
    }
    else if ((status = keystore_load_key(key, &flags, key_handle)) != THSM_STATUS_OK)
    {
        response.payload.hmac_sha1_generate.status = status;
    }
    else
    {
        /* init hmac */
        uint8_t flags = request.payload.hmac_sha1_generate.flags;
        if (flags & THSM_HMAC_RESET)
        {
            hmac_sha1_init(&hmac_sha1_ctx, key, sizeof(key));
        }

        /* clear key */
        memset(key, 0, sizeof(key));

        /* update hmac */
        hmac_sha1_update(&hmac_sha1_ctx, src_data, length);

        /* finalize hmac */
        if (flags & THSM_HMAC_FINAL)
        {
            if (flags & THSM_HMAC_SHA1_TO_BUFFER)
            {
                hmac_sha1_final(&hmac_sha1_ctx, thsm_buffer.data);
                thsm_buffer.data_len = THSM_SHA1_HASH_SIZE;
            }
            else
            {
                hmac_sha1_final(&hmac_sha1_ctx, dst_data);
                response.payload.hmac_sha1_generate.data_len = THSM_SHA1_HASH_SIZE;
                response.bcnt += THSM_SHA1_HASH_SIZE;
            }
        }
    }

    /* clear key */
    memset(key, 0, sizeof(key));
}

static void cmd_ecb_encrypt()
{
    uint8_t key[THSM_KEY_SIZE];
    uint32_t flags;

    /* common response values */
    response.bcnt = sizeof(response.payload.ecb_encrypt) + 1;
    response.payload.ecb_encrypt.status = THSM_STATUS_OK;

    uint8_t *src_key = request.payload.ecb_encrypt.key_handle;
    uint8_t *dst_key = response.payload.ecb_encrypt.key_handle;
    uint8_t *plaintext = request.payload.ecb_encrypt.plaintext;
    uint8_t *ciphertext = response.payload.ecb_encrypt.ciphertext;

    /* copy key handle */
    memcpy(dst_key, src_key, THSM_KEY_HANDLE_SIZE);

    uint8_t status = THSM_STATUS_OK;
    uint32_t key_handle = read_uint32(src_key);
    if (!flags_is_storage_decrypted())
    {
        response.payload.ecb_encrypt.status = THSM_STATUS_KEY_STORAGE_LOCKED;
    }
    else if (request.bcnt != (sizeof(request.payload.ecb_encrypt) + 1))
    {
        response.payload.ecb_encrypt.status = THSM_STATUS_INVALID_PARAMETER;
    }
    else if ((status = keystore_load_key(key, &flags, key_handle)) != THSM_STATUS_OK)
    {
        response.payload.ecb_encrypt.status = status;
    }
    else
    {
        /* perform encryption */
        aes_ecb_encrypt(ciphertext, plaintext, key, sizeof(key));
    }

    /* clear key */
    memset(key, 0, sizeof(key));
}

static void cmd_ecb_decrypt()
{
    uint8_t key[THSM_KEY_SIZE];
    uint32_t flags;

    /* common response values */
    response.bcnt = sizeof(response.payload.ecb_decrypt) + 1;
    response.payload.ecb_decrypt.status = THSM_STATUS_OK;

    uint8_t *src_key = request.payload.ecb_decrypt.key_handle;
    uint8_t *dst_key = response.payload.ecb_decrypt.key_handle;
    uint8_t *plaintext = response.payload.ecb_decrypt.plaintext;
    uint8_t *ciphertext = request.payload.ecb_decrypt.ciphertext;

    /* copy key handle */
    memcpy(dst_key, src_key, THSM_KEY_HANDLE_SIZE);

    uint8_t status = THSM_STATUS_OK;
    uint32_t key_handle = read_uint32(src_key);
    if (!flags_is_storage_decrypted())
    {
        response.payload.ecb_decrypt.status = THSM_STATUS_KEY_STORAGE_LOCKED;
    }
    else if (request.bcnt != (sizeof(request.payload.ecb_decrypt) + 1))
    {
        response.payload.ecb_decrypt.status = THSM_STATUS_INVALID_PARAMETER;
    }
    else if ((status = keystore_load_key(key, &flags, key_handle)) != THSM_STATUS_OK)
    {
        response.payload.ecb_decrypt.status = status;
    }
    else
    {
        /* perform decryption */
        aes_ecb_decrypt(plaintext, ciphertext, key, THSM_KEY_SIZE);
    }

    /* clear key */
    memset(key, 0, sizeof(key));
}

static void cmd_ecb_decrypt_cmp()
{
    uint8_t key[THSM_KEY_SIZE];
    uint32_t flags;

    /* common response values */
    response.bcnt = sizeof(response.payload.ecb_decrypt_cmp) + 1;

    uint8_t *src_key = request.payload.ecb_decrypt_cmp.key_handle;
    uint8_t *dst_key = response.payload.ecb_decrypt_cmp.key_handle;
    uint8_t *plaintext = request.payload.ecb_decrypt_cmp.plaintext;
    uint8_t *ciphertext = request.payload.ecb_decrypt_cmp.ciphertext;

    /* copy key handle */
    memcpy(dst_key, src_key, THSM_KEY_HANDLE_SIZE);

    uint8_t status = THSM_STATUS_OK;
    uint32_t key_handle = read_uint32(src_key);
    if (!flags_is_storage_decrypted())
    {
        response.payload.ecb_decrypt_cmp.status = THSM_STATUS_KEY_STORAGE_LOCKED;
    }
    else if (request.bcnt != (sizeof(request.payload.ecb_decrypt_cmp) + 1))
    {
        response.payload.ecb_decrypt_cmp.status = THSM_STATUS_INVALID_PARAMETER;
    }
    else if ((status = keystore_load_key(key, &flags, key_handle)) != THSM_STATUS_OK)
    {
        response.payload.ecb_decrypt_cmp.status = status;
    }
    else
    {

        /* perform decryption */
        uint8_t recovered[THSM_BLOCK_SIZE];
        aes_ecb_decrypt(recovered, ciphertext, key, sizeof(key));

        /* compare plaintext */
        uint8_t matched = memcmp(recovered, plaintext, THSM_BLOCK_SIZE);
        response.payload.ecb_decrypt_cmp.status = matched ? THSM_STATUS_MISMATCH : THSM_STATUS_OK;

        /* clear temporary variables */
        memset(recovered, 0, sizeof(recovered));
    }

    /* clear key */
    memset(key, 0, sizeof(key));
}

static void cmd_buffer_load()
{
    /* limit offset */
    uint8_t max_offset = sizeof(request.payload.buffer_load.data) - 1;
    uint8_t curr_offset = request.payload.buffer_load.offset;
    uint8_t offset = (curr_offset > max_offset) ? max_offset : curr_offset;

    /* offset + length must be sizeof(request.payload.buffer_load.data) */
    uint8_t max_length = sizeof(request.payload.buffer_load.data) - offset;
    uint8_t curr_length = request.payload.buffer_load.data_len;
    uint8_t length = (curr_length > max_length) ? max_length : curr_length;

    /* set request length */
    request.bcnt = request.payload.buffer_load.data_len + 3;

    /* copy data to buffer */
    uint8_t *src_data = request.payload.buffer_load.data;
    memcpy(&thsm_buffer.data[offset], src_data, length);
    thsm_buffer.data_len = (offset > 0) ? (thsm_buffer.data_len + length) : length;

    /* prepare response */
    response.bcnt = sizeof(response.payload.buffer_load) + 1;
    response.payload.buffer_load.length = thsm_buffer.data_len;
}

static void cmd_buffer_random_load()
{
    /* limit offset */
    uint8_t max_offset = sizeof(thsm_buffer.data) - 1;
    uint8_t curr_offset = request.payload.buffer_random_load.offset;
    uint8_t offset = (curr_offset > max_offset) ? max_offset : curr_offset;

    /* offset + length must be sizeof(thsm_buffer.data) */
    uint8_t max_length = sizeof(thsm_buffer.data) - offset;
    uint8_t curr_length = request.payload.buffer_random_load.length;
    uint8_t length = (curr_length > max_length) ? max_length : curr_length;

    /* fill buffer with random */
    drbg_read(&thsm_buffer.data[offset], length);
    thsm_buffer.data_len = (offset > 0) ? (thsm_buffer.data_len + length) : length;

    /* prepare response */
    response.bcnt = sizeof(response.payload.buffer_random_load) + 1;
    response.payload.buffer_random_load.length = thsm_buffer.data_len;
}

static void cmd_hsm_unlock()
{
    uint8_t key[THSM_KEY_SIZE];
    uint8_t nonce[THSM_AEAD_NONCE_SIZE];

    /* prepare response */
    response.bcnt = sizeof(response.payload.hsm_unlock) + 1;

    uint8_t *public_id = request.payload.hsm_unlock.public_id;
    uint8_t *otp = request.payload.hsm_unlock.otp;
    uint8_t status = THSM_STATUS_OK;

    /* check request byte count */
    if (!flags_is_storage_decrypted())
    {
        response.payload.hsm_unlock.status = THSM_STATUS_KEY_STORAGE_LOCKED;
    }
    else if (request.bcnt != (sizeof(request.payload.hsm_unlock) + 1))
    {
        response.payload.hsm_unlock.status = THSM_STATUS_INVALID_PARAMETER;
    }
    else if ((status = keystore_load_secret(key, nonce, public_id)) != THSM_STATUS_OK)
    {
        response.payload.hsm_unlock.status = status;
    }
    else
    {
        uint8_t decoded[THSM_BLOCK_SIZE];
        uint8_t *uid_act = decoded + 2;
        uint32_t counter = read_uint32(uid_act + THSM_AEAD_NONCE_SIZE);
        uint8_t length = THSM_KEY_SIZE - sizeof(uint16_t);

        /* decrypt otp */
        aes_ecb_decrypt(decoded, otp, key, THSM_KEY_SIZE);

        /* lock secret by default */
        flags_set_secret_locked(true);

        /* compare CRC16 */
        uint16_t crc = (decoded[0] << 8) | decoded[1];
        if (crc != CRC16.ccitt(uid_act, length))
        {
            response.payload.hsm_unlock.status = THSM_STATUS_OTP_INVALID;
        }
        else if (!memcmp(nonce, uid_act, THSM_AEAD_NONCE_SIZE))
        {
            response.payload.hsm_unlock.status = THSM_STATUS_OTP_INVALID;
        }
        else if ((status = keystore_check_counter(public_id, counter)) != THSM_STATUS_OK)
        {
            response.payload.hsm_unlock.status = status;
        }
        else
        {
            secret_locked(false);

            /* save updated flash cache */
            keystore_update();
        }

        /* clear temporary variable */
        memset(decoded, 0, sizeof(decoded));
    }

    /* clear secret */
    memset(key, 0, sizeof(key));
    memset(nonce, 0, sizeof(nonce));
}

static void cmd_key_store_decrypt()
{
    /* prepare response */
    response.bcnt = sizeof(response.payload.key_store_decrypt) + 1;

    /* check request byte count */
    if (request.bcnt != (sizeof(request.payload.key_store_decrypt) + 1))
    {
        response.payload.key_store_decrypt.status = THSM_STATUS_INVALID_PARAMETER;
    }
    else
    {
        /* unlock keystore */
        uint8_t *key = request.payload.key_store_decrypt.key;
        uint8_t status = keystore_unlock(key);
        if (status == THSM_STATUS_OK)
        {
            system_flags |= SYSTEM_FLAGS_STORAGE_DECRYPTED;
        }
        else
        {
            system_flags &= ~SYSTEM_FLAGS_STORAGE_DECRYPTED;
        }
        response.payload.key_store_decrypt.status = status;
    }
}

static void cmd_nonce_get()
{
    /* prepare response */
    response.bcnt = sizeof(response.payload.nonce_get) + 1;
    response.payload.nonce_get.status = THSM_STATUS_OK;

    if (request.bcnt != (sizeof(request.payload.nonce_get) + 1))
    {
        response.payload.nonce_get.status = THSM_STATUS_INVALID_PARAMETER;
    }
    else
    {
        uint16_t step = (request.payload.nonce_get.post_inc[0] << 8) | request.payload.nonce_get.post_inc[1];
        nonce_pool_read(response.payload.nonce_get.nonce, step);
    }
}

static void cmd_buffer_aead_generate()
{
    uint8_t key[THSM_KEY_SIZE];
    uint32_t flags;

    /* prepare response */
    response.bcnt = (sizeof(response.payload.buffer_aead_generate) - sizeof(response.payload.buffer_aead_generate.data)) + 1;
    response.payload.buffer_aead_generate.status = THSM_STATUS_OK;

    uint8_t *src_nonce = request.payload.buffer_aead_generate.nonce;
    uint8_t *dst_nonce = response.payload.buffer_aead_generate.nonce;
    uint8_t *src_key = request.payload.buffer_aead_generate.key_handle;
    uint8_t *dst_key = response.payload.buffer_aead_generate.key_handle;
    uint8_t *dst_data = response.payload.buffer_aead_generate.data;

    /* copy key handle and nonce */
    memcpy(dst_key, src_key, THSM_KEY_HANDLE_SIZE);
    memcpy(dst_nonce, src_nonce, THSM_AEAD_NONCE_SIZE);

    /* get key handle, status and length */
    uint32_t key_handle = read_uint32(src_key);
    uint8_t status = THSM_STATUS_OK;
    uint16_t length = thsm_buffer.data_len;

    /* check parameters */
    if (!(system_flags & SYSTEM_FLAGS_STORAGE_DECRYPTED))
    {
        response.payload.buffer_aead_generate.status = THSM_STATUS_KEY_STORAGE_LOCKED;
    }
    else if (request.bcnt != (sizeof(request.payload.buffer_aead_generate) + 1))
    {
        response.payload.buffer_aead_generate.status = THSM_STATUS_INVALID_PARAMETER;
    }
    else if (length < 1)
    {
        response.payload.buffer_aead_generate.status = THSM_STATUS_INVALID_PARAMETER;
    }
    else if ((status = keystore_load_key(key, &flags, key_handle)) != THSM_STATUS_OK)
    {
        response.payload.buffer_aead_generate.status = status;
    }
    else
    {
        /* generate nonce */
        if (!memcmp(dst_nonce, null_nonce, THSM_AEAD_NONCE_SIZE))
        {
            nonce_pool_read(dst_nonce, 1);
        }

        /* perform CCM encryption */
        aes128_ccm_encrypt(dst_data, NULL, thsm_buffer.data, length, dst_key, key, dst_nonce);

        /* set response */
        response.payload.buffer_aead_generate.data_len = (length + THSM_AEAD_MAC_SIZE);
        response.bcnt += response.payload.buffer_aead_generate.data_len;
    }

    /* clear key */
    memset(key, 0, sizeof(key));
}

static void cmd_random_aead_generate()
{
    uint8_t key[THSM_KEY_SIZE];
    uint32_t flags;

    /* prepare response */
    response.bcnt = (sizeof(response.payload.random_aead_generate) - sizeof(response.payload.random_aead_generate.data)) + 1;
    response.payload.random_aead_generate.status = THSM_STATUS_OK;

    uint8_t *src_nonce = request.payload.random_aead_generate.nonce;
    uint8_t *dst_nonce = response.payload.random_aead_generate.nonce;
    uint8_t *src_key = request.payload.random_aead_generate.key_handle;
    uint8_t *dst_key = response.payload.random_aead_generate.key_handle;
    uint8_t *dst_data = response.payload.random_aead_generate.data;

    /* copy key handle and nonce */
    memcpy(dst_key, src_key, THSM_KEY_HANDLE_SIZE);
    memcpy(dst_nonce, src_nonce, THSM_AEAD_NONCE_SIZE);

    /* get key handle, status and length */
    uint32_t key_handle = read_uint32(src_key);
    uint8_t status = THSM_STATUS_OK;
    uint16_t length = request.payload.random_aead_generate.random_len;

    /* check parameters */
    if (!(system_flags & SYSTEM_FLAGS_STORAGE_DECRYPTED))
    {
        response.payload.random_aead_generate.status = THSM_STATUS_KEY_STORAGE_LOCKED;
    }
    else if (request.bcnt != (sizeof(request.payload.random_aead_generate) + 1))
    {
        response.payload.random_aead_generate.status = THSM_STATUS_INVALID_PARAMETER;
    }
    else if ((length < 1) || (length > THSM_DATA_BUF_SIZE))
    {
        response.payload.random_aead_generate.status = THSM_STATUS_INVALID_PARAMETER;
    }
    else if ((status = keystore_load_key(key, &flags, key_handle)) != THSM_STATUS_OK)
    {
        response.payload.random_aead_generate.status = status;
    }
    else
    {
        /* generate nonce */
        if (!memcmp(dst_nonce, null_nonce, THSM_AEAD_NONCE_SIZE))
        {
            nonce_pool_read(dst_nonce, 1);
        }

        /* genarate random */
        uint8_t random_buffer[THSM_DATA_BUF_SIZE];
        drbg_read(random_buffer, length);

        /* perform AES CCM encryption */
        aes128_ccm_encrypt(dst_data, NULL, random_buffer, length, dst_key, key, dst_nonce);

        /* set response */
        response.payload.random_aead_generate.data_len = length + THSM_AEAD_MAC_SIZE;
        response.bcnt += (length + THSM_AEAD_MAC_SIZE);

        /* clear random buffer */
        memset(random_buffer, 0, sizeof(random_buffer));
    }

    /* clear key */
    memset(key, 0, sizeof(key));
}

static void cmd_aead_decrypt_cmp()
{
    uint8_t key[THSM_KEY_SIZE];
    uint32_t flags;

    /* prepare response */
    response.bcnt = sizeof(response.payload.aead_decrypt_cmp) + 1;

    uint8_t *src_nonce = request.payload.aead_decrypt_cmp.nonce;
    uint8_t *dst_nonce = response.payload.aead_decrypt_cmp.nonce;
    uint8_t *src_key = request.payload.aead_decrypt_cmp.key_handle;
    uint8_t *dst_key = response.payload.aead_decrypt_cmp.key_handle;
    uint8_t *src_data = request.payload.aead_decrypt_cmp.data;

    /* copy key handle and nonce */
    memcpy(dst_key, src_key, THSM_KEY_HANDLE_SIZE);
    memcpy(dst_nonce, src_nonce, THSM_AEAD_NONCE_SIZE);
    uint8_t min_length = sizeof(request.payload.aead_decrypt_cmp) - sizeof(request.payload.aead_decrypt_cmp.data);

    /* get key handle */
    uint32_t key_handle = read_uint32(src_key);
    uint8_t status = THSM_STATUS_OK;
    uint16_t data_length = request.payload.aead_decrypt_cmp.data_len;

    /* check parameters */
    if (!(system_flags & SYSTEM_FLAGS_STORAGE_DECRYPTED))
    {
        response.payload.aead_decrypt_cmp.status = THSM_STATUS_KEY_STORAGE_LOCKED;
    }
    else if (request.bcnt != (min_length + request.payload.aead_decrypt_cmp.data_len + 1))
    {
        response.payload.aead_decrypt_cmp.status = THSM_STATUS_INVALID_PARAMETER;
    }
    else if ((data_length < 8) || (data_length > 72) || (data_length & 0x01))
    {
        response.payload.aead_decrypt_cmp.status = THSM_STATUS_KEY_HANDLE_INVALID;
    }
    else if ((status = keystore_load_key(key, &flags, key_handle)) != THSM_STATUS_OK)
    {
        response.payload.aead_decrypt_cmp.status = status;
    }
    else
    {
        /* calculate length */
        uint8_t length = (data_length - THSM_AEAD_MAC_SIZE) >> 1;

        uint8_t recovered[32];
        uint8_t *plaintext = src_data;
        uint8_t *ciphertext = plaintext + length;
        uint8_t *mac = ciphertext + length;

        /* initialize */
        memset(recovered, 0, sizeof(recovered));

        /* generate nonce */
        if (!memcmp(dst_nonce, null_nonce, THSM_AEAD_NONCE_SIZE))
        {
            nonce_pool_read(dst_nonce, 1);
        }

        /* perform AES CCM decryption */
        uint8_t mac_matched = aes128_ccm_decrypt(recovered, ciphertext, length, dst_key, key, dst_nonce, mac);
        uint8_t pt_matched = !memcmp(recovered, plaintext, length);

        /* set response */
        response.payload.aead_decrypt_cmp.status = (mac_matched && pt_matched) ? THSM_STATUS_OK : THSM_STATUS_MISMATCH;

        /* clear temporary variables */
        memset(recovered, 0, sizeof(recovered));
    }

    /* clear key */
    memset(key, 0, sizeof(key));
}

static void cmd_temp_key_load()
{
    uint8_t key[THSM_KEY_SIZE];
    uint32_t flags;

    /* prepare response */
    response.bcnt = sizeof(response.payload.temp_key_load) + 1;
    response.payload.temp_key_load.status = THSM_STATUS_OK;

    uint8_t *src_key = request.payload.temp_key_load.key_handle;
    uint8_t *dst_key = response.payload.temp_key_load.key_handle;
    uint8_t *src_nonce = request.payload.temp_key_load.nonce;
    uint8_t *dst_nonce = response.payload.temp_key_load.nonce;
    uint8_t *src_data = request.payload.temp_key_load.data;

    /* copy key handle and nonce */
    memcpy(dst_key, src_key, THSM_KEY_HANDLE_SIZE);
    memcpy(dst_nonce, src_nonce, THSM_AEAD_NONCE_SIZE);

    uint32_t key_handle = read_uint32(src_key);
    uint8_t status = THSM_STATUS_OK;
    uint16_t data_len = request.payload.temp_key_load.data_len;

    if (!(system_flags & SYSTEM_FLAGS_STORAGE_DECRYPTED))
    {
        response.payload.temp_key_load.status = THSM_STATUS_KEY_STORAGE_LOCKED;
    }
    else if (request.bcnt != sizeof(request.payload.temp_key_load) + 1)
    {
        response.payload.temp_key_load.status = THSM_STATUS_INVALID_PARAMETER;
    }
    else if ((data_len != 12) || (data_len != 28) || (data_len != 32) || (data_len != 36) || (data_len != 44))
    {
        response.payload.hmac_sha1_generate.status = THSM_STATUS_INVALID_PARAMETER;
    }
    else if ((status = keystore_load_key(key, &flags, key_handle)) != THSM_STATUS_OK)
    {
        response.payload.hmac_sha1_generate.status = status;
    }
    else
    {

        /* clear temporary key and quit */
        if (data_len == 12)
        {
            keystore_store_key(0xffffffff, 0, NULL);
            return;
        }

        /* generate nonce */
        if (!memcmp(dst_nonce, null_nonce, THSM_AEAD_NONCE_SIZE))
        {
            nonce_pool_read(dst_nonce, 1);
        }

        uint8_t length = data_len - (THSM_KEY_HANDLE_SIZE + THSM_AEAD_MAC_SIZE);
        uint8_t ciphertext[32];
        uint8_t plaintext[32];
        uint8_t mac[THSM_AEAD_MAC_SIZE];
        uint8_t flags[THSM_KEY_FLAGS_SIZE];

        /* initialize */
        memset(ciphertext, 0, sizeof(ciphertext));
        memset(plaintext, 0, sizeof(plaintext));

        /* load mac and ciphertext */
        memcpy(ciphertext, src_data, length);
        memcpy(mac, src_data + length, THSM_AEAD_MAC_SIZE);
        memcpy(flags, src_data + length + THSM_AEAD_MAC_SIZE, THSM_KEY_FLAGS_SIZE);

        /* perform AES CCM decryption */
        uint8_t matched = aes128_ccm_decrypt(plaintext, ciphertext, length, dst_key, key, dst_nonce, mac);

        /* Copy to temporary key */
        if (matched)
        {
            keystore_store_key(0xffffffff, 0, plaintext);
        }

        /* set response */
        response.payload.temp_key_load.status = matched ? THSM_STATUS_OK : THSM_STATUS_MISMATCH;

        /* clear temporary variables */
        memset(ciphertext, 0, sizeof(ciphertext));
        memset(plaintext, 0, sizeof(plaintext));
        memset(mac, 0, sizeof(mac));
        memset(flags, 0, sizeof(flags));
    }

    /* clear key */
    memset(key, 0, sizeof(key));
}

static void cmd_db_aead_store()
{
    uint8_t key[THSM_KEY_SIZE];
    uint32_t flags;

    uint8_t *src_key = request.payload.db_aead_store.key_handle;
    uint8_t *dst_key = response.payload.db_aead_store.key_handle;
    uint8_t *src_data = request.payload.db_aead_store.aead;
    uint8_t *src_pub = request.payload.db_aead_store.public_id;
    uint8_t *dst_pub = response.payload.db_aead_store.public_id;

    /* copy key handle and public id */
    memcpy(dst_key, src_key, THSM_KEY_HANDLE_SIZE);
    memcpy(dst_pub, src_pub, THSM_PUBLIC_ID_SIZE);

    /* get key handle */
    uint32_t key_handle = read_uint32(src_key);
    uint8_t status = THSM_STATUS_OK;

    /* load key */
    if (!(system_flags & SYSTEM_FLAGS_STORAGE_DECRYPTED))
    {
        response.payload.db_aead_store.status = THSM_STATUS_KEY_STORAGE_LOCKED;
    }
    else if (request.bcnt > (sizeof(request.payload.db_aead_store) + 1))
    {
        response.payload.db_aead_store.status = THSM_STATUS_INVALID_PARAMETER;
    }
    else if ((status = keystore_load_key(key, &flags, key_handle)) != THSM_STATUS_OK)
    {
        response.payload.db_aead_store.status = status;
    }
    else
    {
        uint8_t length = (THSM_KEY_SIZE + THSM_AEAD_NONCE_SIZE);
        uint8_t *ciphertext = src_data;
        uint8_t *mac = src_data + length;
        uint8_t recovered[THSM_KEY_SIZE + THSM_AEAD_NONCE_SIZE];

        /* clear buffer */
        memset(recovered, 0, sizeof(recovered));

        /* perform AES CCM decryption */
        uint8_t matched = aes128_ccm_decrypt(recovered, ciphertext, length, dst_key, key, src_pub, mac);
        if (matched)
        {
            uint8_t *key = recovered;
            uint8_t *nonce = recovered + THSM_KEY_SIZE;
            status = keystore_store_secret(src_pub, key, nonce, 0);
            response.payload.db_aead_store.status = status;

            /* save updated flash cache */
            if (status == THSM_STATUS_OK)
            {
                keystore_update();
            }
        }
        else
        {
            response.payload.db_aead_store.status = THSM_STATUS_AEAD_INVALID;
        }

        /* clear recovered */
        memset(recovered, 0, sizeof(recovered));
    }

    /* clear key */
    memset(key, 0, sizeof(key));
}

static void cmd_db_aead_store2()
{
    uint8_t key[THSM_KEY_SIZE];
    uint32_t flags;

    uint8_t *src_key = request.payload.db_aead_store2.key_handle;
    uint8_t *dst_key = response.payload.db_aead_store2.key_handle;
    uint8_t *src_data = request.payload.db_aead_store2.aead;
    uint8_t *src_pub = request.payload.db_aead_store2.public_id;
    uint8_t *dst_pub = response.payload.db_aead_store2.public_id;
    uint8_t *src_nonce = request.payload.db_aead_store2.nonce;

    /* copy key handle and public id */
    memcpy(dst_key, src_key, THSM_KEY_HANDLE_SIZE);
    memcpy(dst_pub, src_pub, THSM_PUBLIC_ID_SIZE);

    /* read key handle */
    uint32_t key_handle = read_uint32(src_key);
    uint8_t status = THSM_STATUS_OK;

    /* load key */
    if (!(system_flags & SYSTEM_FLAGS_STORAGE_DECRYPTED))
    {
        response.payload.db_aead_store2.status = THSM_STATUS_KEY_STORAGE_LOCKED;
    }
    else if (request.bcnt > (sizeof(request.payload.db_aead_store) + 1))
    {
        response.payload.db_aead_store2.status = THSM_STATUS_INVALID_PARAMETER;
    }
    else if ((status = keystore_load_key(key, &flags, key_handle)) != THSM_STATUS_OK)
    {
        response.payload.db_aead_store2.status = status;
    }
    else
    {
        uint8_t length = (THSM_KEY_SIZE + THSM_AEAD_NONCE_SIZE);
        uint8_t *ciphertext = src_data;
        uint8_t *mac = src_data + length;
        uint8_t recovered[THSM_KEY_SIZE + THSM_PUBLIC_ID_SIZE];

        /* init buffer */
        memset(recovered, 0, sizeof(recovered));

        /* perform AES CCM decryption */
        uint8_t matched = aes128_ccm_decrypt(recovered, ciphertext, length, dst_key, key, src_nonce, mac);
        if (matched)
        {
            uint8_t *key = recovered;
            uint8_t *nonce = recovered + THSM_KEY_SIZE;
            uint8_t status = keystore_store_secret(src_pub, key, nonce, 0);
            response.payload.db_aead_store.status = status;

            /* save updated flash cache */
            if (status == THSM_STATUS_OK)
            {
                keystore_update();
            }
        }
        else
        {
            response.payload.db_aead_store.status = THSM_STATUS_AEAD_INVALID;
        }

        /* clear recovered */
        memset(recovered, 0, sizeof(recovered));
    }

    /* clear key */
    memset(key, 0, sizeof(key));
}

static void cmd_aead_otp_decode()
{
    uint32_t flags = 0;
    uint8_t key[THSM_KEY_SIZE];

    uint8_t *src_key = request.payload.aead_otp_decode.key_handle;
    uint8_t *dst_key = response.payload.aead_otp_decode.key_handle;
    uint8_t *src_pub = request.payload.aead_otp_decode.public_id;
    uint8_t *dst_pub = response.payload.aead_otp_decode.public_id;
    uint8_t *src_otp = request.payload.aead_otp_decode.otp;
    uint8_t *src_aead = request.payload.aead_otp_decode.aead;

    /* copy key handle, public id */
    memcpy(dst_key, src_key, THSM_KEY_HANDLE_SIZE);
    memcpy(dst_pub, src_pub, THSM_PUBLIC_ID_SIZE);

    /* get key handle */
    uint8_t status = THSM_STATUS_OK;
    uint32_t key_handle = read_uint32(src_key);

    /* check parameters */
    if (!(system_flags & SYSTEM_FLAGS_STORAGE_DECRYPTED))
    {
        response.payload.aead_otp_decode.status = THSM_STATUS_KEY_STORAGE_LOCKED;
    }
    else if (request.bcnt > (sizeof(request.payload.aead_otp_decode) + 1))
    {
        response.payload.aead_otp_decode.status = THSM_STATUS_INVALID_PARAMETER;
    }
    else if ((status = keystore_load_key(key, &flags, key_handle)) != THSM_STATUS_OK)
    {
        response.payload.aead_otp_decode.status = status;
    }
    else
    {
        uint8_t recovered[THSM_KEY_SIZE + THSM_PUBLIC_ID_SIZE];
        uint8_t length = (THSM_KEY_SIZE + THSM_PUBLIC_ID_SIZE);
        uint8_t *ciphertext = src_aead;
        uint8_t *mac = src_aead + length;
        uint8_t *public_id = recovered + THSM_KEY_SIZE;

        /* init buffer */
        memset(recovered, 0, sizeof(recovered));

        /* perform AES CCM decryption */
        uint8_t matched = aes128_ccm_decrypt(recovered, ciphertext, length, dst_key, key, src_pub, mac);
        if (matched)
        {
            uint8_t decoded[THSM_BLOCK_SIZE]; // CRC16 || uid || counter || rand

            /* perform AES ECB decryption */
            aes_ecb_decrypt(decoded, src_otp, recovered, THSM_KEY_SIZE);

            /* compare CRC-16 */
            uint16_t crc = (decoded[0] << 8) | decoded[1];
            if (crc != CRC16.ccitt(decoded + 2, 14))
            {
                response.payload.aead_otp_decode.status = THSM_STATUS_OTP_INVALID;
            }
            else if (memcmp(public_id, decoded + 2, THSM_PUBLIC_ID_SIZE))
            {
                response.payload.aead_otp_decode.status = THSM_STATUS_OTP_INVALID;
            }
            else
            {
                /* copy counter */
                memcpy(response.payload.aead_otp_decode.counter_timestamp, decoded + 8, THSM_PUBLIC_ID_SIZE);
            }

            /* clear temporary buffer */
            memset(decoded, 0, sizeof(decoded));
        }
        else
        {
            response.payload.aead_otp_decode.status = THSM_STATUS_AEAD_INVALID;
        }

        /* clear*/
        memset(recovered, 0, sizeof(recovered));
    }

    /* clear temporary buffer */
    memset(key, 0, sizeof(key));
}

static void cmd_db_otp_validate()
{
    uint8_t key[THSM_KEY_SIZE];
    uint8_t nonce[THSM_AEAD_NONCE_SIZE];

    uint8_t *src_pub = request.payload.db_otp_validate.public_id;
    uint8_t *dst_pub = response.payload.db_otp_validate.public_id;
    uint8_t *src_otp = request.payload.db_otp_validate.otp;

    /* copy public id */
    memcpy(dst_pub, src_pub, THSM_PUBLIC_ID_SIZE);

    /* get key handle */
    uint8_t status = THSM_STATUS_OK;

    /* check parameters */
    if (!(system_flags & SYSTEM_FLAGS_STORAGE_DECRYPTED))
    {
        response.payload.db_otp_validate.status = THSM_STATUS_KEY_STORAGE_LOCKED;
    }
    else if (request.bcnt > (sizeof(request.payload.db_otp_validate) + 1))
    {
        response.payload.db_otp_validate.status = THSM_STATUS_INVALID_PARAMETER;
    }
    else if ((status = keystore_load_secret(key, nonce, src_pub)) != THSM_STATUS_OK)
    {
        response.payload.db_otp_validate.status = status;
    }
    else
    {
        uint8_t decoded[THSM_BLOCK_SIZE]; // CRC16 || uid || counter || rand
        uint8_t *uid_act = decoded + 2;

        /* perform AES ECB decryption */
        aes_ecb_decrypt(decoded, src_otp, key, THSM_KEY_SIZE);

        /* compare CRC-16 */
        uint16_t crc = (decoded[0] << 8) | decoded[1];
        if (crc != CRC16.ccitt(decoded + 2, 14))
        {
            response.payload.db_otp_validate.status = THSM_STATUS_OTP_INVALID;
        }
        else if (memcmp(nonce, uid_act, THSM_PUBLIC_ID_SIZE))
        {
            response.payload.db_otp_validate.status = THSM_STATUS_OTP_INVALID;
        }
        else
        {
            /* copy counter */
            memcpy(response.payload.db_otp_validate.counter_timestamp, decoded + 8, THSM_PUBLIC_ID_SIZE);
        }

        /* clear temporary buffer */
        memset(decoded, 0, sizeof(decoded));
    }

    /* clear key buffer */
    memset(key, 0, sizeof(key));
    memset(nonce, 0, sizeof(nonce));
}
