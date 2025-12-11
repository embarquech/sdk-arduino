#ifndef CRYPTNOXWALLET_H
#define CRYPTNOXWALLET_H

#include "PN532Base.h"
#include <Arduino.h>
#include "uECC.h"

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
    * @brief Retrieves the card's ephemeral public key with a GET CARD CERTIFICATE APDU.
    *
    * Sends a GET CARD CERTIFICATE command to the card, validates the response,
    * and extracts the ephemeral EC P-256 public key used for ECDH in the secure channel.
    *
    * @param[out] cardEphemeralPubKey Buffer to store the 65-byte card ephemeral public key.
    * @param[in,out] cardEphemeralPubKeyLength Input: size of the buffer; Output: actual key length (65 bytes).
    * @return true if the APDU exchange and key extraction succeeded, false otherwise.
    */
    bool getCardCertificate(uint8_t* cardEphemeralPubKey, uint8_t &cardEphemeralPubKeyLength);

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
    * @brief Retrieves the initial 32-byte salt from the card for starting a secure channel.
    *
    * This function sends the APDU command to the card to get the session salt, which is
    * required for the subsequent key derivation in the secure channel setup.
    *
    * @param[out] salt Pointer to a 32-byte buffer where the card-provided salt will be stored.
    * @return true if the APDU exchange succeeded and the salt was retrieved, false otherwise.
    */
    bool openSecureChannel(uint8_t* salt, uint8_t* clientPublicKey, uint8_t* clientPrivateKey, const uECC_Curve_t* sessionCurve);

    bool mutuallyAuthenticate(uint8_t* salt, uint8_t* clientPublicKey, uint8_t* clientPrivateKey, const uECC_Curve_t* sessionCurve, uint8_t* cardEphemeralPubKey);

    /**
    * @brief Extracts the card's ephemeral EC P-256 public key from the certificate.
    *
    * @param[in]  cardCertificate        Pointer to the full card certificate response.
    * @param[out] cardEphemeralPubKey    Buffer to store **64 bytes** (X||Y coordinates only, no 0x04 prefix)
    *                                    for use with uECC_shared_secret. Must be at least 64 bytes.
    * @param[out] cardEphemeralPubKey    Optional buffer to store **65 bytes** including the 0x04 prefix.
    *                                    Can be nullptr if not needed.
    */
    bool extractCardEphemeralKey(const uint8_t* cardCertificate, uint8_t* cardEphemeralPubKey, uint8_t* cardEphemeralPubKey = nullptr);

    /**
    * @brief Print an APDU in hex format with optional label.
    * @param apdu Pointer to the APDU bytes.
    * @param length Number of bytes in the APDU.
    * @param label Optional label for printing (default: "APDU to send").
    */
    void printApdu(const uint8_t* apdu, uint8_t length, const char* label = "APDU to send");

    /**
    * @brief Checks the status word (SW1/SW2) at the end of an APDU response.
    * 
    * @param response        Pointer to the APDU response buffer.
    * @param responseLength  Actual length of the response buffer.
    * @param sw1Expected     Expected value for SW1 (e.g., 0x90).
    * @param sw2Expected     Expected value for SW2 (e.g., 0x00).
    * @return true if the last two bytes match SW1/SW2, false otherwise.
    */
    bool checkStatusWord(const uint8_t* response, uint8_t responseLength, uint8_t sw1Expected, uint8_t sw2Expected);

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
