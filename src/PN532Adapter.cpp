#include "PN532Adapter.h"

/**
 * @brief Construct a PN532Adapter using hardware SPI.
 *
 * @param serialDriver Reference to SerialDriver for debug output.
 * @param ssPin SPI slave select pin connected to the PN532 module.
 * @param theSPI Pointer to SPIClass instance (default: &SPI).
 */
PN532Adapter::PN532Adapter(CW_Logger& serialDriver, uint8_t ssPin, SPIClass *theSPI)
{
    serial    = &serialDriver;
    interface = PN532Interface::SPI_HARDWARE;
    nfc       = new Adafruit_PN532(ssPin, theSPI);
}

/**
 * @brief Construct a PN532Adapter using software SPI (bit-banged).
 *
 * @param serialDriver Reference to SerialDriver for debug output.
 * @param clk Clock pin.
 * @param miso MISO pin.
 * @param mosi MOSI pin.
 * @param ss SPI slave select pin.
 */
PN532Adapter::PN532Adapter(CW_Logger& serialDriver, uint8_t clk, uint8_t miso, uint8_t mosi, uint8_t ss)
{
    serial    = &serialDriver;
    interface = PN532Interface::SPI_SOFTWARE;
    nfc       = new Adafruit_PN532(clk, miso, mosi, ss);
}

/**
 * @brief Construct a PN532Adapter using I2C.
 *
 * @param serialDriver Reference to SerialDriver for debug output.
 * @param irqPin IRQ pin (if applicable).
 * @param resetPin Reset pin of PN532.
 * @param wire Pointer to TwoWire instance (default: &Wire).
 */
PN532Adapter::PN532Adapter(CW_Logger& serialDriver, uint8_t irqPin, uint8_t resetPin, TwoWire *wire)
{
    serial    = &serialDriver;
    interface = PN532Interface::I2C;
    nfc       = new Adafruit_PN532(irqPin, resetPin, wire);
}

/**
 * @brief Construct a PN532Adapter using UART.
 *
 * @param serialDriver Reference to SerialDriver for debug output.
 * @param resetPin Reset pin of PN532.
 * @param uartSerial Pointer to HardwareSerial instance to use.
 */
PN532Adapter::PN532Adapter(CW_Logger& serialDriver, uint8_t resetPin, HardwareSerial *uartSerial)
{
    serial    = &serialDriver;
    interface = PN532Interface::UART;
    nfc       = new Adafruit_PN532(resetPin, uartSerial);
}

/**
 * @brief Destructor. Cleans up the dynamically allocated Adafruit_PN532 instance.
 */
PN532Adapter::~PN532Adapter() {
    if (nfc) {
        delete nfc;
        nfc = NULL;
    }
}

/**
 * @brief Initialize the PN532 module.
 *
 * Calls Adafruit_PN532::begin() and checks firmware.
 *
 * @return true if the module is detected and initialized.
 * @return false otherwise.
 */
bool PN532Adapter::begin() {
    bool ret = false;
    if (nfc != NULL) {
        nfc->begin();
        ret = (nfc->getFirmwareVersion() != 0);
    }
    return ret;
}

/**
 * @brief Send an APDU command to a card and receive its response.
 *
 * @param apdu Pointer to APDU command buffer.
 * @param apduLength Length of APDU command in bytes.
 * @param response Buffer to receive the card's response.
 * @param responseLength Variable to store the length of the response.
 * @return true if APDU exchange succeeded.
 * @return false otherwise.
 */
bool PN532Adapter::sendAPDU(const uint8_t* apdu, uint16_t apduLength,
                            uint8_t* response, uint16_t &responseLength) {
    bool ret = false;
    if ((nfc != NULL) && (serial != NULL) && (apdu != NULL) && (response != NULL)) {
        uint16_t respLen = responseLength;
        bool success = nfc->inDataExchange(const_cast<uint8_t*>(apdu), (uint8_t)apduLength, response, &respLen);
        responseLength = respLen;

        if (!success) {
            serial->println(F("APDU exchange failed!"));
        } else {
            serial->print(F("APDU response ("));
            serial->print(responseLength);
            serial->println(F(" bytes):"));

            for (uint16_t i = 0; i < responseLength; i++) {
                serial->print(F("0x"));
                if (response[i] < 16) serial->print(F("0"));
                serial->print(response[i], HEX);
                serial->print(F(" "));
                if ((i + 1) % 16 == 0 && (i + 1) != responseLength) serial->println();
            }
            serial->println();
            ret = true;
        }
    }
    return ret;
}

/**
 * @brief Check if a passive target (card) is present.
 *
 * @return true if a card is detected.
 * @return false otherwise.
 */
bool PN532Adapter::inListPassiveTarget() {
    bool ret = false;
    if (nfc != NULL) {
        ret = nfc->inListPassiveTarget();
    }
    return ret;
}

/**
 * @brief Reset the PN532 reader and configure it.
 */
void PN532Adapter::resetReader() {
    if (nfc != NULL) {
        nfc->SAMConfig();
    }
}

/**
 * @brief Print firmware and chip information to Serial.
 *
 * @return true if information was successfully retrieved.
 * @return false if the PN532 module was not detected.
 */
bool PN532Adapter::printFirmwareVersion() {
    bool result = false;
    if ((nfc != NULL) && (serial != NULL)) {
        uint32_t versionData = nfc->getFirmwareVersion();

        if (versionData != false) {
            uint8_t ic       = (versionData >> 24U) & 0xFFU;
            uint8_t verMajor = (versionData >> 16U) & 0xFFU;
            uint8_t verMinor = (versionData >>  8U) & 0xFFU;
            uint8_t flags    =  versionData        & 0xFFU;
            bool first       = true;

            serial->println(F("PN532 information"));
            serial->print(F(" ├─ Raw firmware: 0x"));
            serial->println(versionData, HEX);

            serial->print(F(" ├─ IC Chip: "));
            if (ic == 0x32U) {
                serial->println(F("PN532"));
            } else {
                serial->println(F("Unknown"));
            }

            serial->print(F(" ├─ Firmware: "));
            serial->print(verMajor);
            serial->print(F("."));
            serial->println(verMinor);

            serial->print(F(" └─ Features: "));
            if ((flags & 0x01U) != 0U) {
                serial->print(F("MIFARE"));
                first = false;
            }
            if ((flags & 0x02U) != 0U) {
                if (!first) {
                    serial->print(F(" + "));
                }
                serial->print(F("ISO-DEP"));
                first = false;
            }
            if ((flags & 0x04U) != 0U) {
                if (!first) {
                    serial->print(F(" + "));
                }
                serial->print(F("FeliCa"));
                first = false;
            }
            if (first) {
                serial->print(F("Unknown"));
            }

            serial->print(F(" (0x"));
            serial->print(flags, HEX);
            serial->println(F(")"));

            nfc->SAMConfig(); /* Configure the PN532 for normal operation */
            result = true;
        } else {
            serial->println(F("PN532 not found!"));
        }
    }

    return result;
}
