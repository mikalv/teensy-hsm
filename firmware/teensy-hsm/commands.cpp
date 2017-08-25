#include <string.h>
#include "commands-private.h"
#include "macros.h"
#include "aes.h"
#include "error.h"
#include "util.h"
#include "crc16.h"

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

// HMAC flag
#define THSM_HMAC_RESET          0x01
#define THSM_HMAC_FINAL          0x02
#define THSM_HMAC_SHA1_TO_BUFFER 0x04

Commands::Commands()
{
    init();
}

void Commands::init()
{
    flags = Flags();
    //drbg.init()
    buffer.init();
    storage.init();
}

void Commands::clear()
{

}

bool Commands::process(uint8_t cmd, packet_t &response, const packet_t &request)
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
        return false;
    }
}

bool Commands::null(packet_t &response, const packet_t &request)
{
    return false;
}

bool Commands::aead_generate(packet_t &output, const packet_t &input)
{
    THSM_AEAD_GENERATE_REQ request;
    THSM_AEAD_GENERATE_RESP response;
    key_info_t key_info;

    uint32_t min_request_length = (sizeof(request) - sizeof(request.data));
    uint32_t min_response_length = (sizeof(response) - sizeof(response.data));

    /* initialize response */
    MEMCLR(response);

    /* check against minimum length */
    if (input.length < min_request_length)
    {
        response.status = THSM_STATUS_INVALID_PARAMETER;
        goto finish;
    }

    /* initialize buffers */
    memcpy(&request, input.bytes, MIN(sizeof(request), input.length));

    /* check against provided length */
    if ((request.data_len > sizeof(request.data)) || (input.length < (request.data_len + min_request_length)))
    {
        response.status = THSM_STATUS_INVALID_PARAMETER;
        goto finish;
    }

    /* get key */
    memcpy(response.key_handle, request.key_handle, sizeof(request.key_handle));
    uint32_t key_handle = READ32(request.key_handle);
    int32_t ret = storage.get_key(key_info, key_handle);
    if (ret == ERROR_CODE_STORAGE_ENCRYPTED)
    {
        response.status = THSM_STATUS_MEMORY_ERROR;
        goto finish;
    }
    else if (ret == ERROR_CODE_KEY_NOT_FOUND)
    {
        response.status = THSM_STATUS_KEY_HANDLE_INVALID;
        goto finish;
    }

    /* generate nonce if it is null */
    if (Util::is_empty(request.nonce, sizeof(request.nonce)))
    {
        if (!drbg.generate(request.nonce, sizeof(request.nonce)))
        {
            response.status = THSM_STATUS_EXT_DRBG_ERROR;
            goto finish;
        }
    }

    uint32_t length = request.data_len;

    /* initialize AES-CCM */
    AESCCM aes = AESCCM();
    aes.encrypt(response.data, request.data, length, key_handle, key_info.bytes, request.nonce);

    /* copy key handle and nonce */
    response.status = THSM_STATUS_OK;
    response.data_len = length + AES_CCM_MAC_SIZE_BYTES;
    memcpy(response.nonce, request.nonce, sizeof(request.nonce));

    finish:

    uint32_t output_length = response.data_len + min_response_length;
    output.length = output_length;
    memcpy(output.bytes, &response, output.length);

    return true;
}

bool Commands::buffer_aead_generate(packet_t &output, const packet_t &input)
{
    THSM_BUFFER_AEAD_GENERATE_REQ request;
    THSM_BUFFER_AEAD_GENERATE_RESP response;
    key_info_t key_info;
    buffer_t plaintext;

    uint32_t min_request_length = sizeof(request);
    uint32_t min_response_length = (sizeof(response) - sizeof(response.data));

    /* initialize response */
    MEMCLR(response);

    /* check against minimum length */
    if (input.length < min_request_length)
    {
        response.status = THSM_STATUS_INVALID_PARAMETER;
        goto finish;
    }

    /* initialize buffers */
    memcpy(&request, input.bytes, MIN(sizeof(request), input.length));

    /* get key */
    memcpy(response.key_handle, request.key_handle, sizeof(request.key_handle));
    uint32_t key_handle = READ32(request.key_handle);
    int32_t ret = storage.get_key(key_info, key_handle);
    if (ret == ERROR_CODE_STORAGE_ENCRYPTED)
    {
        response.status = THSM_STATUS_MEMORY_ERROR;
        goto finish;
    }
    else if (ret == ERROR_CODE_KEY_NOT_FOUND)
    {
        response.status = THSM_STATUS_KEY_HANDLE_INVALID;
        goto finish;
    }

    /* generate nonce if it is null */
    if (Util::is_empty(request.nonce, sizeof(request.nonce)))
    {
        if (!drbg.generate(request.nonce, sizeof(request.nonce)))
        {
            response.status = THSM_STATUS_EXT_DRBG_ERROR;
            goto finish;
        }
    }

    /* encode buffer */
    buffer.read(plaintext);

    /* encrypt */
    uint32_t length = plaintext.length;
    AESCCM aes = AESCCM();
    aes.encrypt(response.data, plaintext.bytes, length, key_handle, key_info.bytes, request.nonce);

    /* copy key handle and nonce */
    response.status = THSM_STATUS_OK;
    response.data_len = length + AES_CCM_MAC_SIZE_BYTES;
    memcpy(response.nonce, request.nonce, sizeof(request.nonce));

    finish:

    uint32_t output_length = response.data_len + min_response_length;
    output.length = output_length;
    memcpy(output.bytes, &response, output.length);

    return true;
}

bool Commands::random_aead_generate(packet_t &output, const packet_t &input)
{
    THSM_RANDOM_AEAD_GENERATE_REQ request;
    THSM_RANDOM_AEAD_GENERATE_RESP response;
    key_info_t key_info;
    buffer_t plaintext;

    uint32_t min_request_length = sizeof(request);
    uint32_t min_response_length = (sizeof(response) - sizeof(response.data));

    /* initialize response */
    MEMCLR(response);

    /* check against minimum length */
    if (input.length < min_request_length)
    {
        response.status = THSM_STATUS_INVALID_PARAMETER;
        goto finish;
    }

    /* copy request */
    memcpy(&request, input.bytes, MIN(sizeof(request), input.length));

    /* can only generate max 64 bytes */
    if (request.random_len > sizeof(plaintext.bytes))
    {
        response.status = THSM_STATUS_INVALID_PARAMETER;
        goto finish;
    }

    /* get key */
    memcpy(response.key_handle, request.key_handle, sizeof(request.key_handle));
    uint32_t key_handle = READ32(request.key_handle);
    int32_t ret = storage.get_key(key_info, key_handle);
    if (ret == ERROR_CODE_STORAGE_ENCRYPTED)
    {
        response.status = THSM_STATUS_MEMORY_ERROR;
        goto finish;
    }
    else if (ret == ERROR_CODE_KEY_NOT_FOUND)
    {
        response.status = THSM_STATUS_KEY_HANDLE_INVALID;
        goto finish;
    }

    /* generate nonce if it is null */
    if (Util::is_empty(request.nonce, sizeof(request.nonce)))
    {
        if (!drbg.generate(request.nonce, sizeof(request.nonce)))
        {
            response.status = THSM_STATUS_EXT_DRBG_ERROR;
            goto finish;
        }
    }

    /* generate random plain-text */
    uint32_t length = request.random_len;
    if (!drbg.generate(plaintext, length))
    {
        response.status = THSM_STATUS_EXT_DRBG_ERROR;
        goto finish;
    }

    /* encrypt generated data */
    AESCCM aes = AESCCM();
    aes.encrypt(response.data, plaintext.bytes, length, key_handle, key_info.bytes, request.nonce);

    /* copy key handle and nonce */
    response.status = THSM_STATUS_OK;
    response.data_len = length + AES_CCM_MAC_SIZE_BYTES;
    memcpy(response.nonce, request.nonce, sizeof(request.nonce));

    finish:

    uint32_t output_length = response.data_len + min_response_length;
    output.length = output_length;
    memcpy(output.bytes, &response, output.length);

    return true;
}

bool Commands::aead_decrypt_cmp(packet_t &output, const packet_t &input)
{
    THSM_AEAD_DECRYPT_CMP_REQ request;
    THSM_AEAD_DECRYPT_CMP_RESP response;
    uint8_t plaintext[THSM_MAX_PKT_SIZE];
    key_info_t key_info;

    uint32_t min_request_length = (sizeof(request) - sizeof(request.data));
    uint32_t min_response_length = sizeof(response);

    /* initialize response */
    MEMCLR(response);

    /* check against minimum length */
    if (input.length <= min_request_length)
    {
        response.status = THSM_STATUS_INVALID_PARAMETER;
        goto finish;
    }

    /* initialize buffers */
    MEMCLR(plaintext);
    memcpy(&request, input.bytes, MIN(sizeof(request), input.length));

    /* check minimum data length, at least 1 byte of cipher-text */
    if ((request.data_len <= AES_CCM_MAC_SIZE_BYTES) || (request.data_len > sizeof(request.data)))
    {
        response.status = THSM_STATUS_INVALID_PARAMETER;
        goto finish;
    }

    /* get key */
    memcpy(response.key_handle, request.key_handle, sizeof(request.key_handle));
    uint32_t key_handle = READ32(request.key_handle);
    int32_t ret = storage.get_key(key_info, key_handle);
    if (ret == ERROR_CODE_STORAGE_ENCRYPTED)
    {
        response.status = THSM_STATUS_MEMORY_ERROR;
        goto finish;
    }
    else if (ret == ERROR_CODE_KEY_NOT_FOUND)
    {
        response.status = THSM_STATUS_KEY_HANDLE_INVALID;
        goto finish;
    }

    /* decipher AEAD */
    uint32_t length = request.data_len;
    AESCCM aes = AESCCM();
    bool match = aes.decrypt(plaintext, request.data, length, key_handle, key_info.bytes, request.nonce);

    /* copy key handle and nonce */
    response.status = match ? THSM_STATUS_OK : THSM_STATUS_AEAD_INVALID;
    memcpy(response.nonce, request.nonce, sizeof(request.nonce));

    finish:

    output.length = min_response_length;
    memcpy(output.bytes, &response, output.length);

    return true;
}

bool Commands::db_aead_store(packet_t &output, const packet_t &input)
{
    THSM_DB_AEAD_STORE_REQ request;
    THSM_DB_AEAD_STORE_RESP response;
    key_info_t key_info;
    uint8_t plaintext[AES_KEY_SIZE_BYTES + AES_CCM_NONCE_SIZE_BYTES];

    uint32_t min_request_length = sizeof(request);
    uint32_t min_response_length = sizeof(response);

    /* initialize response */
    MEMCLR(response);

    /* check against minimum length */
    if (input.length < min_request_length)
    {
        response.status = THSM_STATUS_INVALID_PARAMETER;
        goto finish;
    }

    /* initialize buffers */
    memcpy(&request, input.bytes, MIN(sizeof(request), input.length));
    memcpy(response.key_handle, request.key_handle, sizeof(request.key_handle));
    memcpy(response.public_id, request.public_id, sizeof(request.public_id));

    /* get key */
    uint32_t key_handle = READ32(request.key_handle);
    int32_t ret = storage.get_key(key_info, key_handle);
    if (ret == ERROR_CODE_STORAGE_ENCRYPTED)
    {
        response.status = THSM_STATUS_MEMORY_ERROR;
        goto finish;
    }
    else if (ret == ERROR_CODE_KEY_NOT_FOUND)
    {
        response.status = THSM_STATUS_KEY_HANDLE_INVALID;
        goto finish;
    }

    /* decipher AEAD */
    uint32_t length = sizeof(request.aead);
    AESCCM aes = AESCCM();
    MEMCLR(plaintext);
    bool match = aes.decrypt(plaintext, request.aead, length, key_handle, key_info.bytes, request.public_id);
    if (match)
    {
        secret_info_t secret_info;
        aes_ccm_nonce_t nonce;

        AESCCM::nonce_copy(nonce, request.public_id);
        Util::unpack_secret(secret_info, plaintext);

        bool stored = storage.put_secret(secret_info, key_info, nonce);
        response.status = stored ? THSM_STATUS_OK : THSM_STATUS_DB_FULL;
    }
    else
    {
        response.status = THSM_STATUS_AEAD_INVALID;
    }

    finish:

    output.length = min_response_length;
    memcpy(output.bytes, &response, output.length);

    return true;
}

bool Commands::aead_otp_decode(packet_t &output, const packet_t &input)
{
    THSM_AEAD_OTP_DECODE_REQ request;
    THSM_AEAD_OTP_DECODE_RESP response;
    key_info_t key_info;
    uint8_t plaintext[AES_KEY_SIZE_BYTES + AES_CCM_NONCE_SIZE_BYTES];

    uint32_t min_request_length = sizeof(request);
    uint32_t min_response_length = sizeof(response);

    /* initialize response */
    MEMCLR(response);

    /* check against minimum length */
    if (input.length < min_request_length)
    {
        response.status = THSM_STATUS_INVALID_PARAMETER;
        goto finish;
    }

    /* initialize buffers */
    memcpy(&request, input.bytes, MIN(sizeof(request), input.length));
    memcpy(response.key_handle, request.key_handle, sizeof(request.key_handle));
    memcpy(response.public_id, request.public_id, sizeof(request.public_id));

    /* get key */
    uint32_t key_handle = READ32(request.key_handle);
    int32_t ret = storage.get_key(key_info, key_handle);
    if (ret == ERROR_CODE_STORAGE_ENCRYPTED)
    {
        response.status = THSM_STATUS_MEMORY_ERROR;
        goto finish;
    }
    else if (ret == ERROR_CODE_KEY_NOT_FOUND)
    {
        response.status = THSM_STATUS_KEY_HANDLE_INVALID;
        goto finish;
    }

    /* decipher OTP */
    uint32_t length = sizeof(request.aead);
    AESCCM ccm = AESCCM();
    MEMCLR(plaintext);
    bool match = ccm.decrypt(plaintext, request.aead, length, key_handle, key_info.bytes, request.public_id);
    if (match)
    {
        secret_info_t secret_info;
        aes_state_t key, pt, ct;
        Util::unpack_secret(secret_info, plaintext);
        AES::state_copy(key, secret_info.key);
        AES::state_copy(pt, request.otp);

        CRC16 crc = CRC16();
        AES ecb = AES();
        ecb.init(key);
        ecb.decrypt(pt, ct);

        // decrypted OTP
        // -------------------------------------------------
        // |00|01|02|03|04|05|06|07|08|09|10|11|12|13|14|15|
        // -------------------------------------------------
        // |       uid       | ctr | tstamp |su| rnd |crc16|
        // -------------------------------------------------

        response.status = THSM_STATUS_OTP_INVALID;
        uint16_t crc_ref = READ16(pt.bytes + 14);
        bool crc_match = crc.ccit(pt.bytes, 14) == crc_ref;
        bool uid_match = memcmp(pt.bytes, secret_info.uid, sizeof(secret_info.uid)) == 0;
        if (crc_match && uid_match)
        {
            response.status = THSM_STATUS_OK;
            memcpy(response.counter_timestamp, (pt.bytes + 8), sizeof(response.counter_timestamp));
        }
        else
        {
            response.status = THSM_STATUS_OTP_INVALID;
        }
    }
    else
    {
        response.status = THSM_STATUS_AEAD_INVALID;
    }

    finish:

    output.length = min_response_length;
    memcpy(output.bytes, &response, output.length);

    return true;
}

bool Commands::db_otp_validate(packet_t &output, const packet_t &input)
{
    THSM_DB_OTP_VALIDATE_REQ request;
    THSM_DB_OTP_VALIDATE_RESP response;

    key_info_t key_info;
    secret_info_t secret_info;

    uint32_t min_request_length = sizeof(request);
    uint32_t min_response_length = sizeof(response);

    /* initialize response */
    MEMCLR(response);

    /* check against minimum length */
    if (input.length < min_request_length)
    {
        response.status = THSM_STATUS_INVALID_PARAMETER;
        goto finish;
    }

    /* initialize buffers */
    memcpy(&request, input.bytes, MIN(sizeof(request), input.length));
    memcpy(response.public_id, request.public_id, sizeof(request.public_id));

    /* get secret */
    aes_ccm_nonce_t public_id;
    AESCCM::nonce_copy(public_id, request.public_id);
    int32_t ret = storage.get_secret(secret_info, public_id);
    if ((ret == ERROR_CODE_KEY_NOT_FOUND) || (ret == ERROR_CODE_WRONG_KEY))
    {
        response.status = THSM_STATUS_MEMORY_ERROR;
        goto finish;
    }
    else if (ret == ERROR_CODE_SECRET_NOT_FOUND)
    {
        response.status = THSM_STATUS_ID_NOT_FOUND;
        goto finish;
    }

    /* decipher OTP */
    aes_state_t key, pt, ct;
    AES::state_copy(key, secret_info.key);
    AES::state_copy(pt, request.otp);

    CRC16 crc = CRC16();
    AES ecb = AES();
    ecb.init(key);
    ecb.decrypt(pt, ct);

    // decrypted OTP
    // -------------------------------------------------
    // |00|01|02|03|04|05|06|07|08|09|10|11|12|13|14|15|
    // -------------------------------------------------
    // |       uid       | ctr | tstamp |su| rnd |crc16|
    // -------------------------------------------------

    response.status = THSM_STATUS_OTP_INVALID;
    uint16_t crc_ref = READ16(pt.bytes + 14);
    bool crc_match = crc.ccit(pt.bytes, 14) == crc_ref;
    bool uid_match = memcmp(pt.bytes, secret_info.uid, sizeof(secret_info.uid)) == 0;
    if (crc_match && uid_match)
    {
        /* check counter */
        uint16_t counter = READ16(pt.bytes + 6);
        storage.check_counter(public_id, counter);
        response.status = THSM_STATUS_OK;
        memcpy(response.counter_timestamp, (pt.bytes + 8), sizeof(response.counter_timestamp));
    }
    else
    {
        response.status = THSM_STATUS_OTP_INVALID;
    }

    finish:

    output.length = min_response_length;
    memcpy(output.bytes, &response, output.length);

    return true;
}

bool Commands::db_aead_store2(packet_t &output, const packet_t &input)
{
    THSM_DB_AEAD_STORE2_REQ request;
    THSM_DB_AEAD_STORE2_RESP response;
    key_info_t key_info;
    uint8_t plaintext[AES_KEY_SIZE_BYTES + AES_CCM_NONCE_SIZE_BYTES];

    /* check against minimum length */
    if (input.length < sizeof(request))
    {
        return ERROR_CODE_INVALID_REQUEST;
    }

    /* initialize buffers */
    MEMCLR(response);
    MEMCLR(plaintext);
    memcpy(&request, input.bytes, MIN(sizeof(request), input.length));

    /* get key */
    uint32_t key_handle = READ32(request.key_handle);
    int ret = storage.get_key(key_info, key_handle);
    if (ret < 0)
    {
        return ret;
    }

    /* decrypt */
    uint32_t length = sizeof(request.aead);
    AESCCM aes = AESCCM();
    bool match = aes.decrypt(plaintext, request.aead, length, key_handle, key_info.bytes, request.public_id);
    if (match)
    {
        secret_info_t secret_info;
        aes_ccm_nonce_t nonce;

        AESCCM::nonce_copy(nonce, request.nonce);
        Util::unpack_secret(secret_info, plaintext);
        int32_t ret = storage.put_secret(secret_info, key_info, nonce);
        if (ret < 0)
        {
            return ret;
        }
    }

    /* copy key handle and nonce */
    response.status = match ? THSM_STATUS_OK : THSM_STATUS_AEAD_INVALID;
    memcpy(response.key_handle, request.key_handle, sizeof(request.key_handle));
    memcpy(response.public_id, request.public_id, sizeof(request.public_id));

    /* copy to output */
    output.length = sizeof(response);
    memcpy(output.bytes, &response, sizeof(response));

    return true;
}

int32_t Commands::aes_ecb_block_encrypt(packet_t &output, const packet_t &input)
{
    THSM_AES_ECB_BLOCK_ENCRYPT_REQ request;
    THSM_AES_ECB_BLOCK_ENCRYPT_RESP response;
    key_info_t key_info;
    aes_state_t pt, ct;

    /* check against minimum length */
    if (input.length < sizeof(request))
    {
        return ERROR_CODE_INVALID_REQUEST;
    }

    memcpy(&request, input.bytes, sizeof(request));
    MEMCLR(response);

    /* get key */
    uint32_t key_handle = READ32(request.key_handle);
    int ret = storage.get_key(key_info, key_handle);
    if (ret < 0)
    {
        return ret;
    }

    AES aes = AES();
    aes.init(key_info.bytes);
    AES::state_copy(pt, request.plaintext);
    aes.encrypt(ct, pt);

    response.status = THSM_STATUS_OK;
    memcpy(response.ciphertext, ct.bytes, sizeof(ct.bytes));
    memcpy(response.key_handle, request.key_handle, sizeof(request.key_handle));

    output.length = sizeof(response);
    memcpy(output.bytes, &response, sizeof(response));

    return ERROR_CODE_NONE;
}

int32_t Commands::aes_ecb_block_decrypt(packet_t &output, const packet_t &input)
{
    THSM_AES_ECB_BLOCK_DECRYPT_REQ request;
    THSM_AES_ECB_BLOCK_DECRYPT_RESP response;
    key_info_t key_info;
    aes_state_t pt, ct;

    /* check against minimum length */
    if (input.length < sizeof(request))
    {
        return ERROR_CODE_INVALID_REQUEST;
    }

    memcpy(&request, input.bytes, sizeof(request));
    MEMCLR(response);

    /* get key */
    uint32_t key_handle = READ32(request.key_handle);
    int ret = storage.get_key(key_info, key_handle);
    if (ret < 0)
    {
        return ret;
    }

    AES aes = AES();
    aes.init(key_info.bytes);
    AES::state_copy(ct, request.ciphertext);
    aes.decrypt(pt, ct);

    response.status = THSM_STATUS_OK;
    memcpy(response.plaintext, pt.bytes, sizeof(pt.bytes));
    memcpy(response.key_handle, request.key_handle, sizeof(request.key_handle));

    output.length = sizeof(response);
    memcpy(output.bytes, &response, sizeof(response));

    return ERROR_CODE_NONE;
}

int32_t Commands::aes_ecb_block_decrypt_cmp(packet_t &output, const packet_t &input)
{
    THSM_AES_ECB_BLOCK_DECRYPT_CMP_REQ request;
    THSM_AES_ECB_BLOCK_DECRYPT_CMP_RESP response;
    key_info_t key_info;
    aes_state_t pt, ct;

    /* check against minimum length */
    if (input.length < sizeof(request))
    {
        return ERROR_CODE_INVALID_REQUEST;
    }

    memcpy(&request, input.bytes, sizeof(request));
    MEMCLR(response);

    /* get key */
    uint32_t key_handle = READ32(request.key_handle);
    int ret = storage.get_key(key_info, key_handle);
    if (ret < 0)
    {
        return ret;
    }

    AES aes = AES();
    aes.init(key_info.bytes);
    AES::state_copy(ct, request.ciphertext);
    aes.decrypt(pt, ct);
    bool match = AES::state_compare(pt, request.plaintext);

    response.status = match ? THSM_STATUS_OK : THSM_STATUS_MISMATCH;
    memcpy(response.key_handle, request.key_handle, sizeof(request.key_handle));

    output.length = sizeof(response);
    memcpy(output.bytes, &response, sizeof(response));

    return ERROR_CODE_NONE;
}

int32_t Commands::hmac_sha1_generate(packet_t &output, const packet_t &input)
{
    THSM_HMAC_SHA1_GENERATE_REQ request;
    THSM_HMAC_SHA1_GENERATE_RESP response;
    key_info_t key_info;

    if (input.length < 6)
    {
        return ERROR_CODE_INVALID_REQUEST;
    }

    MEMCLR(response);
    memcpy(&request, input.bytes, sizeof(request));

    if (request.data_len > sizeof(request.data))
    {
        return ERROR_CODE_INVALID_REQUEST;
    }

    /* get key */
    uint32_t key_handle = READ32(request.key_handle);
    int ret = storage.get_key(key_info, key_handle);
    if (ret < 0)
    {
        return ret;
    }

    uint8_t flags = request.flags;
    if (!flags)
    {
        hmac.update(request.data, request.data_len);
    }

    if (flags & THSM_HMAC_RESET)
    {
        hmac.init(key_info.bytes, sizeof(key_info.bytes));
    }

    if (flags & THSM_HMAC_FINAL)
    {
        sha1_digest_t hash;
        hmac.final(hash);

        response.data_len = sizeof(hash.bytes);
        memcpy(response.data, hash.bytes, sizeof(hash.bytes));

        if (flags & THSM_HMAC_SHA1_TO_BUFFER)
        {
            buffer.clear();
            buffer.write(0, hash.bytes, sizeof(hash.bytes));
        }
    }

    response.status = THSM_STATUS_OK;
    memcpy(response.key_handle, request.key_handle, sizeof(request.key_handle));

    /* copy to output buffer */
    uint32_t output_length = response.data_len + 6;
    memcpy(output.bytes, &response, output_length);
    output.length = output_length;

    return ERROR_CODE_NONE;
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

int32_t Commands::echo(packet_t &output, const packet_t &input)
{
    THSM_ECHO_RESP request;
    THSM_ECHO_RESP response;

    if (input.length < 1)
    {
        return ERROR_CODE_INVALID_REQUEST;
    }

    MEMCLR(response);
    memcpy(&request, input.bytes, sizeof(request));

    if (request.data_len > sizeof(request.data))
    {
        return ERROR_CODE_INVALID_REQUEST;
    }

    /* set response */
    uint32_t length = request.data_len;
    response.data_len = length;
    memcpy(response.data, request.data, length);

    /* opy to output */
    memcpy(output.bytes, &response, length + 1);
    output.length = length + 1;

    return ERROR_CODE_NONE;
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
    MEMCLR(response);
    memcpy(&request, input.bytes, sizeof(request));

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

int32_t Commands::random_reseed(packet_t &output, const packet_t &input)
{
    THSM_RANDOM_RESEED_REQ request;
    THSM_RANDOM_RESEED_RESP response;
    aes_drbg_entropy_t entropy;

    if (input.length < sizeof(request))
    {
        return ERROR_CODE_INVALID_REQUEST;
    }

    MEMCLR(response);
    memcpy(&request, input.bytes, sizeof(request));
    memcpy(entropy.bytes, request.seed, sizeof(entropy.bytes));

    /* reseed */
    drbg.reseed(entropy);

    response.status = THSM_STATUS_OK;
    output.length = sizeof(response);
    memcpy(output.bytes, &response, sizeof(response));
    return ERROR_CODE_NONE;
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
