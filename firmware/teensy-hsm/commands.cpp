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

        int32_t ret = storage.put_secret(secret_info, key_info, nonce);
        if (ret == ERROR_CODE_STORAGE_ENCRYPTED)
        {
            response.status = THSM_STATUS_MEMORY_ERROR;
        }
        else if (ret == ERROR_CODE_SECRET_SLOT_FULL)
        {
            response.status = THSM_STATUS_DB_FULL;
        }
        else
        {
            response.status = THSM_STATUS_OK;
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
        uint32_t hi = READ16(pt.bytes + 6);
        uint16_t lo = READ16(pt.bytes + 12);
        uint16_t ret = storage.check_counter(public_id, (hi << 16) + lo);
        if (ret == ERROR_CODE_STORAGE_ENCRYPTED)
        {
            response.status = THSM_STATUS_MEMORY_ERROR;
        }
        else if (ret == ERROR_CODE_SECRET_NOT_FOUND)
        {
            response.status = THSM_STATUS_ID_NOT_FOUND;
        }
        else if (ret == ERROR_CODE_OTP_PLAYBACK)
        {
            response.status = THSM_STATUS_OTP_REPLAY;
        }
        else
        {
            response.status = THSM_STATUS_OK;
            memcpy(response.counter_timestamp, (pt.bytes + 8), sizeof(response.counter_timestamp));
        }
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
    AESCCM ccm = AESCCM();
    MEMCLR(plaintext);
    bool match = ccm.decrypt(plaintext, request.aead, length, key_handle, key_info.bytes, request.public_id);
    if (match)
    {
        secret_info_t secret_info;
        aes_ccm_nonce_t nonce;

        AESCCM::nonce_copy(nonce, request.nonce);
        Util::unpack_secret(secret_info, plaintext);
        int32_t ret = storage.put_secret(secret_info, key_info, nonce);
        if (ret == ERROR_CODE_STORAGE_ENCRYPTED)
        {
            response.status = THSM_STATUS_MEMORY_ERROR;
        }
        else if (ret == ERROR_CODE_SECRET_SLOT_FULL)
        {
            response.status = THSM_STATUS_DB_FULL;
        }
        else
        {
            response.status = THSM_STATUS_OK;
        }
    }

    finish:

    output.length = min_response_length;
    memcpy(output.bytes, &response, output.length);

    return true;
}

bool Commands::aes_ecb_block_encrypt(packet_t &output, const packet_t &input)
{
    THSM_AES_ECB_BLOCK_ENCRYPT_REQ request;
    THSM_AES_ECB_BLOCK_ENCRYPT_RESP response;
    key_info_t key_info;
    aes_state_t pt, ct;

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
    memcpy(&request, input.bytes, sizeof(request));
    memcpy(response.key_handle, request.key_handle, sizeof(request.key_handle));

    /* get key */
    uint32_t key_handle = READ32(request.key_handle);
    int ret = storage.get_key(key_info, key_handle);
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

    AES aes = AES();
    aes.init(key_info.bytes);
    AES::state_copy(pt, request.plaintext);
    aes.encrypt(ct, pt);

    response.status = THSM_STATUS_OK;
    memcpy(response.ciphertext, ct.bytes, sizeof(ct.bytes));

    finish:

    output.length = min_response_length;
    memcpy(output.bytes, &response, output.length);

    return true;
}

bool Commands::aes_ecb_block_decrypt(packet_t &output, const packet_t &input)
{
    THSM_AES_ECB_BLOCK_DECRYPT_REQ request;
    THSM_AES_ECB_BLOCK_DECRYPT_RESP response;
    key_info_t key_info;
    aes_state_t pt, ct;

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
    memcpy(&request, input.bytes, sizeof(request));
    memcpy(response.key_handle, request.key_handle, sizeof(request.key_handle));

    /* get key */
    uint32_t key_handle = READ32(request.key_handle);
    int ret = storage.get_key(key_info, key_handle);
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

    AES aes = AES();
    aes.init(key_info.bytes);
    AES::state_copy(ct, request.ciphertext);
    aes.decrypt(pt, ct);

    response.status = THSM_STATUS_OK;
    memcpy(response.plaintext, pt.bytes, sizeof(pt.bytes));

    finish:

    output.length = min_response_length;
    memcpy(output.bytes, &response, output.length);

    return true;
}

bool Commands::aes_ecb_block_decrypt_cmp(packet_t &output, const packet_t &input)
{
    THSM_AES_ECB_BLOCK_DECRYPT_CMP_REQ request;
    THSM_AES_ECB_BLOCK_DECRYPT_CMP_RESP response;
    key_info_t key_info;
    aes_state_t pt, ct;

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
    memcpy(&request, input.bytes, sizeof(request));
    memcpy(response.key_handle, request.key_handle, sizeof(request.key_handle));

    /* get key */
    uint32_t key_handle = READ32(request.key_handle);
    int ret = storage.get_key(key_info, key_handle);
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

    AES aes = AES();
    aes.init(key_info.bytes);
    AES::state_copy(ct, request.ciphertext);
    aes.decrypt(pt, ct);
    bool match = AES::state_compare(pt, request.plaintext);
    response.status = match ? THSM_STATUS_OK : THSM_STATUS_MISMATCH;

    finish:

    output.length = min_response_length;
    memcpy(output.bytes, &response, output.length);

    return true;
}

bool Commands::hmac_sha1_generate(packet_t &output, const packet_t &input)
{
    THSM_HMAC_SHA1_GENERATE_REQ request;
    THSM_HMAC_SHA1_GENERATE_RESP response;
    key_info_t key_info;

    uint32_t min_request_length = sizeof(request) - sizeof(request.data);
    uint32_t min_response_length = sizeof(response) - sizeof(response.data);

    /* initialize response */
    MEMCLR(response);

    /* check against minimum length */
    if (input.length < min_request_length)
    {
        response.status = THSM_STATUS_INVALID_PARAMETER;
        goto finish;
    }

    /* initialize buffers */
    memcpy(&request, input.bytes, sizeof(request));
    memcpy(response.key_handle, request.key_handle, sizeof(request.key_handle));

    /* check against available buffer size */
    if (request.data_len > sizeof(request.data))
    {
        response.status = THSM_STATUS_INVALID_PARAMETER;
        goto finish;
    }

    /* get key */
    uint32_t key_handle = READ32(request.key_handle);
    uint32_t ret = storage.get_key(key_info, key_handle);
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

    finish:

    output.length = response.data_len + min_response_length;
    memcpy(output.bytes, &response, output.length);

    return true;
}

bool Commands::temp_key_load(packet_t &output, const packet_t &input)
{
    THSM_TEMP_KEY_LOAD_REQ request;
    THSM_TEMP_KEY_LOAD_RESP response;
    uint8_t key_and_flag[AES_KEY_SIZE_BYTES + sizeof(uint32_t)];
    key_info_t key_info;

    uint32_t min_request_length = sizeof(request) - sizeof(request.data);
    uint32_t min_response_length = sizeof(response);

    MEMCLR(request);
    MEMCLR(response);

    if (input.length < min_request_length)
    {
        response.status = THSM_STATUS_INVALID_PARAMETER;
        goto finish;
    }

    /* initialize buffers */
    memcpy(&request, input.bytes, sizeof(request));
    memcpy(response.key_handle, request.key_handle, sizeof(request.key_handle));
    memcpy(response.nonce, request.nonce, sizeof(request.nonce));

    /* for this time */
    if (request.data_len == 0)
    {
        response.status = THSM_STATUS_OK;
        storage.clear_key(TEMP_KEY_HANDLE);
        goto finish;
    }
    else if (request.data_len != sizeof(request.data))
    {
        response.status = THSM_STATUS_INVALID_PARAMETER;
        goto finish;
    }
    else if (Util::is_empty(request.data, sizeof(request.data)))
    {
        response.status = THSM_STATUS_OK;
        storage.clear_key(TEMP_KEY_HANDLE);
        goto finish;
    }

    /* get key */
    uint32_t key_handle = READ32(request.key_handle);
    uint32_t ret = storage.get_key(key_info, key_handle);
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

    /* decipher data and put it on temporary key */
    AESCCM ccm = AESCCM();
    MEMCLR(key_and_flag);
    if (!ccm.decrypt(key_and_flag, request.data, request.data_len, key_handle, key_info.bytes, request.nonce))
    {
        response.status = THSM_STATUS_MISMATCH;
        goto finish;
    }
    response.status = THSM_STATUS_OK;

    /* put temporary key to storage */
    key_info.handle = TEMP_KEY_HANDLE;
    key_info.flags = READ32(key_and_flag + AES_KEY_SIZE_BYTES);
    memcpy(key_info.bytes, key_and_flag, AES_KEY_SIZE_BYTES);
    storage.put_key(key_info);

    finish:

    output.length = sizeof(response);
    memcpy(output.bytes, &response, output.length);

    return true;
}

bool Commands::buffer_load(packet_t &output, const packet_t &input)
{
    THSM_BUFFER_LOAD_REQ request;
    THSM_BUFFER_LOAD_RESP response;

    uint32_t min_request_length = sizeof(request) - sizeof(request.data);
    uint32_t min_response_length = sizeof(response);

    MEMCLR(request);
    MEMCLR(response);

    if (input.length < min_request_length)
    {
        goto finish;
    }

    /* initialize buffers */
    memcpy(&request, input.bytes, sizeof(request));
    if ((request.data_len > sizeof(request.data)) || (request.offset > sizeof(request)))
    {
        goto finish;
    }

    uint32_t available = sizeof(request.data) - request.offset;
    uint32_t length = MIN(available, request.data_len);

    /* store to buffer */
    buffer.write(request.offset, request.data, length);

    finish:

    output.length = sizeof(response);
    memcpy(output.bytes, &response, output.length);

    return true;
}

bool Commands::buffer_random_load(packet_t &output, const packet_t &input)
{
    THSM_BUFFER_RANDOM_LOAD_REQ request;
    THSM_BUFFER_RANDOM_LOAD_RESP response;
    uint8_t random[BUFFER_SIZE_BYTES];

    uint32_t min_request_length = sizeof(request);
    uint32_t min_response_length = sizeof(response);

    MEMCLR(request);
    MEMCLR(response);
    MEMCLR(random);

    if (input.length < min_request_length)
    {
        goto finish;
    }

    /* initialize buffers */
    memcpy(&request, input.bytes, sizeof(request));
    if ((request.length > BUFFER_SIZE_BYTES) || (request.offset > BUFFER_SIZE_BYTES))
    {
        goto finish;
    }

    /* generate random */
    uint32_t available = sizeof(random) - request.offset;
    uint32_t step = MIN(available, request.length);
    if (drbg.generate(random, step))
    {
        buffer.write(request.offset, random, step);
        response.length = step;
    }
    else
    {
        response.length = 0;
    }

    finish:

    output.length = sizeof(response);
    memcpy(output.bytes, &response, output.length);
    return true;
}

bool Commands::nonce_get(packet_t &response, const packet_t &request)
{
    /* FIXME add implementation */
    return true;
}

bool Commands::echo(packet_t &output, const packet_t &input)
{
    THSM_ECHO_REQ request;
    THSM_ECHO_RESP response;

    uint32_t min_request_length = sizeof(request) - sizeof(request.data);
    uint32_t min_response_length = sizeof(response) - sizeof(response.data);

    /* initialize response */
    MEMCLR(request);
    MEMCLR(response);

    /* check against minimum length */
    if (input.length < min_request_length)
    {
        goto finish;
    }

    memcpy(&request, input.bytes, sizeof(request));

    /* set response */
    uint32_t length = MIN(request.data_len, sizeof(request.data));
    response.data_len = length;
    memcpy(response.data, request.data, length);

    finish:

    output.length = length + min_response_length;
    memcpy(output.bytes, &response, output.length);

    return true;
}

bool Commands::random_generate(packet_t &output, const packet_t &input)
{
    THSM_RANDOM_GENERATE_REQ request;
    THSM_RANDOM_GENERATE_RESP response;

    uint32_t min_request_length = sizeof(request);
    uint32_t min_response_length = sizeof(response) - sizeof(response.bytes);

    /* initialize request and response */
    MEMCLR(request);
    MEMCLR(response);

    if (input.length < min_request_length)
    {
        goto finish;
    }

    /* initialize buffer */
    memcpy(&request, input.bytes, sizeof(request));

    /* truncate requested length */
    uint8_t *ptr = response.bytes;
    uint32_t length = MIN(request.bytes_len, sizeof(response.bytes));
    uint32_t remaining = length;

    while (remaining)
    {
        aes_state_t random;
        int32_t ret = drbg.generate(random);
        if (ret < 0)
        {
            return ret;
        }

        uint32_t step = MIN(remaining, sizeof(random.bytes));
        memcpy(ptr, random.bytes, step);

        ptr += step;
        remaining -= step;
        response.bytes_len += step;
    }

    finish:

    output.length = response.bytes_len + min_response_length;
    memcpy(output.bytes, &response, output.length);

    return true;
}

bool Commands::random_reseed(packet_t &output, const packet_t &input)
{
    THSM_RANDOM_RESEED_REQ request;
    THSM_RANDOM_RESEED_RESP response;
    aes_drbg_entropy_t entropy;

    MEMCLR(request);
    MEMCLR(response);

    if (input.length < sizeof(request))
    {
        response.status = THSM_STATUS_INVALID_PARAMETER;
        goto finish;
    }

    /* initialize buffers */
    memcpy(&request, input.bytes, sizeof(request));
    memcpy(entropy.bytes, request.seed, sizeof(entropy.bytes));

    /* reseed */
    drbg.reseed(entropy);
    response.status = THSM_STATUS_OK;

    finish:

    output.length = sizeof(response);
    memcpy(output.bytes, &response, sizeof(response));
    return ERROR_CODE_NONE;
}

bool Commands::system_info_query(packet_t &response, const packet_t &request)
{
    /* FIXME add implementation */
    return true;
}

bool Commands::hsm_unlock(packet_t &response, const packet_t &request)
{
    /* FIXME add implementation */
    return true;
}

bool Commands::key_store_decrypt(packet_t &response, const packet_t &request)
{
    /* FIXME add implementation */
    return true;
}

bool Commands::monitor_exit(packet_t &response, const packet_t &request)
{
    /* FIXME add implementation */
    return true;
}
