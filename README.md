# teensy-hsm
A Teensyduino based Yubikey HSM emulator. This code in under heavy development, some function may not working properly

## Implemented Commands
- Get System Information
- Echo
- Random Generation
- Random Reseed
- ECB Encryption (limited to phantom key handle 0xffffffff)
- ECB Decryption (limited to phantom key handle 0xffffffff)
- ECB decrypt & compare (limited to phantom key handle 0xffffffff)
- Buffer loading
- Buffer random loading
- HMAC-SHA1 (limited to phantom key handle 0xffffffff)
- HSM unlock (dummy command)
- Keystore decrypt (dummy command)
- Nonce get (nonce returned from ADC rng)
- AEAD generate (limited to phantom key handle 0xffffffff)
- AEAD generate from buffer (limited to phantom key handle 0xffffffff)
- AEAD generate from random (limited to phantom key handle 0xffffffff)
- AEAD decrypt and compare (limited to phantom key handle 0xffffffff)
- Temporary key loading

## How to Flash
- Get Teensy duino [v3.1](http://www.pjrc.com/store/teensy31.html) or [v3.2](http://www.pjrc.com/store/teensy32.html)
- Follow Teensyduino [getting started](http://www.pjrc.com/teensy/td_download.html)
- Clone the project
- Open cloned project with Arduino IDE, set the following parameters:
    - **Board** : Teensy 3.2/3.1
    - **USB Type** : Serial
- Click Compile/Verify and press reset button
- To test flashed software, you can use python-pyhsm 

## How to enter debugging console
- Plug flashed Teensy HSM
- Open /dev/ttyACMx from minicom
- Press tab multiple times until '$' sign appeared
- To quit debugging console, press tab until 'exit' sign appeared

## Debugging session example

```
Welcome to minicom 2.7

OPTIONS: I18n 
Compiled on Feb  7 2016, 13:37:27.
Port /dev/ttyACM0, 23:44:24

Press CTRL-A Z for help on special keys


$ aes.ecb.encrypt 00000000000000000000000000000000 10a58869d74be5a374cf867cfb473859
6D251E6944B051E04EAA6FB4DBF78465
$ aes.ecb.decrypt 6d251e6944b051e04eaa6fb4dbf78465 10a58869d74be5a374cf867cfb473859
00000000000000000000000000000000
$ 
exit
```
