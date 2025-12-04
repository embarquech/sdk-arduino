<p align="center">
  <img src="https://github.com/user-attachments/assets/6ce54a27-8fb6-48e6-9d1f-da144f43425a"/>
</p>

<h3 align="center">cryptnox-sdk-arduino</h3>
<p align="center">Arduino library for managing Cryptnox smart card wallets</p>

<br/>
<br/>

[![License: GPLv3](https://img.shields.io/badge/License-LGPLv3-blue.svg)](https://www.gnu.org/licenses/lgpl-3.0)

`cryptnox-sdk-arduino` is a library that enables the use of **Cryptnox Smart cards** on Arduino platforms.  
It allows performing basic operations with the card, such as secure communication, retrieving card information, and simple cryptographic functions.

---

## Supported hardware

- **Cryptnox Smart cards** 💳
- **Standard PC/SC Smart card Readers**: either USB NFC reader or a USB smart card reader
  → Readers are also available in the Cryptnox shop.

Get your card and readers here: [shop.cryptnox.com](https://shop.cryptnox.com)

---

## Dependencies

Before using `cryptnox-sdk-arduino`, you must install the following libraries via the **Arduino Library Manager**:

- **AESLib**
- **Adafruit_BusIO**
- **Adafruit_PN532**
- **Crypto**
- **PN532Base**
- **micro-ecc**

---

## Installation

1. Download or clone this repository.  
2. Copy the `cryptnox-sdk-arduino` folder into your Arduino `libraries` directory.  
3. Restart the Arduino IDE to detect the library.

---

## Basic Example

```cpp
#include <AESLib.h>
#include <Adafruit_PN532.h>
#include <Crypto.h>
#include <uECC.h>

void setup() {
  Serial.begin(9600);
  Serial.println("Cryptnox-wallet initialization...");
}

void loop() {
  // Insert your card handling logic here
}
```

## Documentation

The generated documentation for this project is available [here](https://embarquech.github.io/sdk-arduino/).

## License

cryptnox-cli is dual-licensed:

- **LGPL-3.0** for open-source projects and proprietary projects that comply with LGPL requirements  
- **Commercial license** for projects that require a proprietary license without LGPL obligations (see COMMERCIAL.md for details)

For commercial inquiries, contact: contact@cryptnox.com
