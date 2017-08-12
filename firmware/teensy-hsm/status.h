#ifndef __STATUS_H__
#define __STATUS_H__

//------------------------------------------------------------------------------
// Status Code
//------------------------------------------------------------------------------
#define THSM_STATUS_OK                 0x80
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

#endif
