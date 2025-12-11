#ifndef CRYPTNOXWALLET_H
#define CRYPTNOXWALLET_H

#include "PN532Base.h"
#include <Arduino.h>

/**
 * @class CryptnoxWallet
 * @brief High-level interface for interacting with a PN532-based wallet.
 *
 * This class encapsulates NFC card operations specific to the Cryptnox wallet,
 * including sending APDUs, retrieving the card certificate, and reading the UID.
 * It supports all bus types provided by Adafruit_PN532 (I2C, SPI, Software SPI, UART)
 * via constructor overloading.
 */
class CryptnoxWallet {
public:
    /**
     * @brief Construct a CryptnoxWallet over I2C.
     *
     * @param irq Pin number for PN532 IRQ (use -1 if unused).
     * @param reset Pin number for PN532 RESET (use -1 if unused).
     * @param theWire TwoWire instance (default is &Wire).
     */
    CryptnoxWallet(uint8_t irq, uint8_t reset, TwoWire *theWire = &Wire)
        : driver(irq, reset, theWire) {}

    /**
     * @brief Construct a CryptnoxWallet over hardware SPI.
     *
     * @param ss SPI slave select pin.
     * @param theSPI SPIClass instance (default is &SPI).
     */
    CryptnoxWallet(uint8_t ss, SPIClass *theSPI = &SPI)
        : driver(ss, theSPI) {}

    /**
     * @brief Construct a CryptnoxWallet over software SPI.
     *
     * @param clk Clock pin.
     * @param miso MISO pin.
     * @param mosi MOSI pin.
     * @param ss SPI slave select pin.
     */
    CryptnoxWallet(uint8_t clk, uint8_t miso, uint8_t mosi, uint8_t ss)
        : driver(clk, miso, mosi, ss) {}

    /**
     * @brief Construct a CryptnoxWallet over UART.
     *
     * @param reset Reset pin for PN532 (use -1 if unused).
     * @param theSer HardwareSerial instance.
     */
    CryptnoxWallet(uint8_t reset, HardwareSerial *theSer)
        : driver(reset, theSer) {}

    /**
     * @brief Initialize the PN532 module via the underlying driver.
     *
     * Performs SAM configuration and checks firmware version.
     *
     * @return true if the module was successfully initialized, false otherwise.
     */
    bool begin() {
        return driver.begin();
    }

    /**
     * @brief Detect and process an NFC card for Cryptnox wallet operations.
     *
     * If an ISO-DEP card is detected, SELECT APDU is sent and certificate is retrieved.
     * If only a passive card is detected, the UID is printed.
     *
     * @return true if a card was successfully processed, false otherwise.
     */
    bool processCard();

    /**
     * @brief Send the SELECT APDU to select the wallet application.
     *
     * @return true if the APDU exchange succeeded, false otherwise.
     */
    bool selectApdu();

    /**
     * @brief Send get card certificate APDU with random challenge.
     * 
     * Generates RANDOM_BYTES random bytes and appends them to the APDU.
     * 
     * @param response Buffer to store the card response.
     * @param responseLength Input: buffer size, Output: actual response length.
     * @return true if the APDU exchange succeeded, false otherwise.
     */
    bool getCardCertificate(uint8_t* response, uint8_t &len);

    /**
     * @brief Read the UID of a detected card.
     *
     * @param uidBuffer Pointer to buffer to store the UID.
     * @param uidLength Reference to variable to store UID length.
     * @return true if the UID was read successfully, false otherwise.
     */
    bool readUID(uint8_t* uidBuffer, uint8_t &uidLength);

    /**
    * @brief Print detailed firmware information of the PN532 module.
    *
    * Retrieves the firmware version, parses IC type, major/minor versions,
    * and supported features, then prints all details to the Serial console.
    *
    * @return true if the PN532 module was detected and information printed, false otherwise.
    */
    bool printPN532FirmwareVersion();

    /**
    * @brief Establish a secure channel with the card using ECC.
    * @return true if successful, false otherwise.
    */
    bool openSecureChannel();

    /**
    * @brief Print an APDU in hex format with optional label.
    * @param apdu Pointer to the APDU bytes.
    * @param length Number of bytes in the APDU.
    * @param label Optional label for printing (default: "APDU to send").
    */
    void printApdu(const uint8_t* apdu, uint8_t length, const char* label = "APDU to send");
    
    /**
    * @brief Derive a pairing key by hashing the PUK 32 times (SHA256^32).
    * 
    * When P1=0xFF, the pairing key is computed as SHA256 applied 32 times
    * to the PUK code. This allows the PUK to be used as a fallback pairing key.
    * 
    * @param puk Pointer to the PUK bytes.
    * @param pukLength Length of the PUK.
    * @param pairingKey Output buffer (must be at least 32 bytes).
    */
    void derivePairingKeyFromPUK(const uint8_t* puk, size_t pukLength, uint8_t* pairingKey); 

private:
    PN532Base driver; /**< PN532 driver for low-level NFC operations */
    
    /**
     * @brief RNG callback for micro-ecc library.
     * @param dest Pointer to buffer to fill with random bytes.
     * @param size Number of bytes to generate.
     * @return 1 on success.
     */
    static int uECC_RNG(uint8_t *dest, unsigned size);

    /** @brief Initialize the ECC RNG for micro-ecc library. */
    void initECC_RNG();
};

#endif // CRYPTNOXWALLET_H
