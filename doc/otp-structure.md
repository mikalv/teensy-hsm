# OTP Details

## Overview

OTP is a 16 bytes ciphertext derived from the following operation

```
otp = aes_128_encrypt(plain_otp, key)
```

## Plain OTP 

Plain OTP is consisted of the following entries:
- 6 bytes of UID (nonce a.k.a private_id of key)
- 2 bytes of counter (little endian)
- 3 bytes of timestamp (little endian) 
- 1 byte of session use
- 2 bytes of random
- 2 bytes of crc16 (little endian)

```
-------------------------------------------------
|00|01|02|03|04|05|06|07|08|09|10|11|12|13|14|15|
-------------------------------------------------
|       uid       | ctr | tstamp |su| rnd |crc16|
-------------------------------------------------
```

## Reference
- [yubico-c](https://developers.yubico.com/yubico-c/)
