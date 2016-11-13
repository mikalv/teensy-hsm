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
