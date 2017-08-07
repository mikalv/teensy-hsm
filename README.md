# teensy-hsm
A Teensyduino based Yubikey HSM emulator. This code in under heavy development, some function may not working properly. TeensyHSM is inspired by [YubiHSM Manual](https://www.yubico.com/wp-content/uploads/2015/04/YubiHSM-Manual_1_5_0.pdf) and [python-pyhsm](https://github.com/Yubico/python-pyhsm)

## Architecture

![TeensyHSM architecture](doc/architecture.png)

## EEPROM Layout
![EEPROM Layout](doc/eeprom_layout.png)

Description:
- EEPROM header contains header identifier and SHA1 digest of decrypted EEPROM body
- EEPROM body contains 32 entries of keys and 32 entries of secrets 

## Disclaimer
Please read this carefully
- TeensyHSM **is not** intended to replace YubiHSM
- TeensyHSM **is not** FIPS 140-2 certified
- TeensyHSM entropy source is based on sampled ADC noise  while YubiHSM uses PN-junction avalance noise based entropy source. If you need security **please use** YubiHSM instead
- TeensyHSM **is not** tamper resistant and **vulnerable** to side channel attack (DPA, EMF emission pickup)
- Use at your own risk

## Algorithms
Teensy HSM uses the following algorithms:
- AES-128 (ECB, CBC, CCM)
- SHA1-HMAC
- SHA1
- AES-128 based SP800-90 CTR-DRBG

## Documentation
- [OTP Structure](doc/otp-structure.md)
- [Supported Commands](https://github.com/edipermadi/teensy-hsm/wiki/Commands)
- [Setup Console](https://github.com/edipermadi/teensy-hsm/wiki/Setup-Console)
- [Debugging Console](https://github.com/edipermadi/teensy-hsm/wiki/Debugging-Console)
- [How To Flash](https://github.com/edipermadi/teensy-hsm/wiki/How-to-Flash)
