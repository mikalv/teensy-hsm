# Changelog

## Nov 10, 2016
- Added hsm unlock command (dummy command, need to add implementation)
- Added keystore decryption command (dummy command, need to add implementation)
- Fixed HMAC-SHA1 generation
- Added ADC rng based nonce get command

## Nov 07, 2016
- Implemented HMAC-SHA1 generation command (limited to phantom key handle 0xffffffff)

## Oct 25, 2016
 - Implemented ECB decrypt and compare command

## Oct 24, 2016
- Whiten ADC noise with CRC32

## Oct 23, 2016
- Implemented ECB encryption command (static dummy key)
- Implemented ECB decryption command (static dummy key)
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
