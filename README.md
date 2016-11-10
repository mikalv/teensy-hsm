# teensy-hsm
A Teensyduino based Yubikey HSM emulator.

## Implemented Commands
- Get System Information
- Echo
- Random Generation
- Random Reseed
- ECB Encryption (dummy static key)
- ECB Decryption (dummy static key)
- ECB decrypt & compare (dummy static key)
- Buffer loading
- Buffer random loading
- HMAC-SHA1 (limited to phantom key handle)
- HSM unlock (dummy command)
- Keystore decrypt (dummy command)

## How to Flash
- Get Teensy duino [v3.1](http://www.pjrc.com/store/teensy31.html) or [v3.2](http://www.pjrc.com/store/teensy32.html)
- Follow Teensyduino [getting started](http://www.pjrc.com/teensy/td_download.html)
- Clone the project
- Open cloned project with Arduino IDE, set the following parameters:
    - **Board** : Teensy 3.2/3.1
    - **USB Type** : Serial
- Click Compile/Verify and press reset button
- To test flashed software, you can use python-pyhsm 
