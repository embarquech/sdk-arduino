// PN532I2C.h
#ifndef PN532I2C_H
#define PN532I2C_H

#include "PN532Base.h"
#include <Wire.h>
#include <Adafruit_PN532.h>

/**
 * @brief Concrete PN532 class using I2C communication.
 * 
 * This class implements the PN532Base interface for I2C.
 * It allows reading NFC card UIDs and firmware version.
 */
class PN532I2C : public PN532Base {
public:
    /**
     * @brief Construct a new PN532I2C object.
     * 
     * @param sdaPin Arduino pin for I2C SDA.
     * @param sclPin Arduino pin for I2C SCL.
     */
    PN532I2C(uint8_t sdaPin, uint8_t sclPin);

    /**
     * @brief Initialize the PN532 module over I2C.
     * 
     * Starts the module, reads firmware version, and configures normal operation.
     * Prints status to Serial.
     * 
     * @return true if the module was successfully initialized, false otherwise.
     */
    bool begin() override;

    /**
     * @brief Read the UID of a detected NFC card.
     * 
     * @param uidBuffer Pointer to a buffer to store the UID.
     * @param uidLength Reference to a variable to store the UID length.
     * @return true if a card was detected and UID read successfully, false otherwise.
     */
    bool readUID(uint8_t* uidBuffer, uint8_t &uidLength) override;

    /**
     * @brief Get the firmware version of the PN532 module.
     * 
     * @param version Reference to a variable that will store the 32-bit firmware version.
     * @return true if the firmware version was successfully retrieved, false otherwise.
     */
    bool getFirmwareVersion(uint32_t &version) override;

    /**
     * @brief Send an APDU command to an ISO14443-4 (Type 4) NFC tag.
     *
     * @param apdu Pointer to the APDU buffer to send.
     * @param apduLength Length of the APDU buffer.
     * @param response Pointer to a buffer that will receive the response APDU.
     * @param responseLength Reference to a variable that will contain the response length.
     * @return true if the APDU exchange succeeded, false otherwise.
     */
    bool sendAPDU(const uint8_t* apdu, uint8_t apduLength,
                  uint8_t* response, uint8_t &responseLength);

    /**
    * @brief Detect an ISO14443-4 / ISO-DEP card and activate it for APDU exchange.
    * 
    * This function wraps the Adafruit PN532 `inListPassiveTarget()` method.
    * It allows the PN532 to communicate with ISO-DEP (Type 4) cards.
    * 
    * @return true if a card was detected and successfully activated, false otherwise.
    */
    bool inListPassiveTarget() override;

private:
    Adafruit_PN532 nfc; /**< Internal Adafruit PN532 object for I2C communication */
};

#endif
