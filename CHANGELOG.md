# Changelog

## Nov 18, 2016
- Implemented `aes.ecb.encrypt` and `aes.ecb.decrypt` debugging command

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
