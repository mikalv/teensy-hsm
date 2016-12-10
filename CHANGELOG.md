# Changelog

## Dec 10, 2016
- Added AES CBC implementation
- Implemented keystore based key loading
- Implemented secret of THSM_CMD_DB_AEAD_STORE and THSM_CMD_DB_AEAD_STORE2
- Implemented AEAD OTP decode and DB OTP validate

## Nov 4, 2016
- Implemented nonce pool

## Nov 26, 2016
- Implemented AES-256 CBC debugging command
- Implemented DRBD reseed and generate debugging command

## Nov 25, 2016
- Implemented AES-256 key derivation
- Implemented AEAD store to DB
- Implemented AEAD store to DB with specified nonce

## Nov 20, 2016
- Implemented SP800-90 based AES-CTR-DRBG
- Added DRBG reseed implementation to random reseed command 

## Nov 19, 2016
- Implemented `flash.dump` debuging command
- Implemented `buffer.dump` debuging command
## Nov 18, 2016
- Implemented The following debugging commands:

    - `aes.ecb.encrypt`
    - `aes.ecb.decrypt`
    - `aes.ccm.encrypt`
    - `aes.ccm.decrypt`
    - `sha1.init`
    - `sha1.update`
    - `sha1.final`
    - `hmac.sha1.init`
    - `hmac.sha1.update`
    - `hmac.sha1.final`
- Fixed `aes_ccm_encrypt` and `aes_ccm_decrypt` implementation issue


## Nov 13, 2016
- Implemented temporary key loading
- Implemented aead_decrypt_cmp
- Do not send MAC unless its final
- Clear phantom key on hsm_unlock

## Nov 12, 2016
- Wrap AES common operation
- Implemented AEAD buffer generate
- Implemented AEAD random generate

## Nov 10, 2016
- Added hsm unlock command (dummy command, need to add implementation)
- Added keystore decryption command (dummy command, need to add implementation)
- Fixed HMAC-SHA1 generation
- Added ADC rng based nonce get command
- Added aead_generate command (limited to phantom key handle 0xffffffff)

## Nov 07, 2016
- Implemented HMAC-SHA1 generation command (limited to phantom key handle 0xffffffff)

## Oct 25, 2016
 - Implemented ECB decrypt and compare command

## Oct 24, 2016
- Whiten ADC noise with CRC32

## Oct 23, 2016
- Implemented ECB encryption command (limited to phantom key handle 0xffffffff)
- Implemented ECB decryption command (limited to phantom key handle 0xffffffff)
- Implemented buffer load command
- Implemented buffer random load command

## Oct 21, 2016
- Added command frame payload length checking
- Added echo payload checking
- Added random generate command (random taken from ADC noise)
- Added random reseed command (dummy response)

## Oct 20, 2016
- Fixed Echo Command
- Fixed Info Query Command
- Rename YSM_XX to TSM_XX

## Oct 19, 2016
- Added Echo Command
- Added Info Query Command
