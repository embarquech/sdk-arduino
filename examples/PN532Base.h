// PN532Base.h
#ifndef PN532BASE_H
#define PN532BASE_H

#include <Arduino.h>

/**
 * @brief Abstract base class for PN532 NFC/RFID modules.
 * 
 * This class defines a common interface for different communication
 * methods (I2C, SPI, HSU). Derived classes implement the specific
 * protocol details.
 */
class PN532Base {
public:
    /**
     * @brief Initialize the PN532 module.
     * 
     * Performs necessary startup routines for the module.
     * 
     * @return true if initialization was successful, false otherwise.
     */
    virtual bool begin() = 0;

    /**
     * @brief Read the UID of a detected NFC card.
     * 
     * @param uidBuffer Pointer to a buffer to store the UID.
     * @param uidLength Reference to a variable to store the UID length.
     * @return true if a card was detected and UID read successfully, false otherwise.
     */
    virtual bool readUID(uint8_t* uidBuffer, uint8_t &uidLength) = 0;

    /**
     * @brief Get the firmware version of the PN532 module.
     * 
     * @param version Reference to a variable that will store the firmware version as a 32-bit value.
     * @return true if firmware version was successfully retrieved, false otherwise.
     */
    virtual bool getFirmwareVersion(uint32_t &version) = 0;

    /**
     * @brief Send an APDU command to an ISO14443-4 compliant tag.
     *
     * Base method to allow APDU exchange with Type 4 NFC tags.
     * Implementations may return false if the interface does not support APDUs.
     *
     * @param apdu Pointer to the APDU command data.
     * @param apduLength Size of the APDU command.
     * @param response Pointer to a buffer that will store the APDU response.
     * @param responseLength Reference that receives the length of the response.
     * @return true if the APDU was successfully exchanged, false otherwise.
     */
    virtual bool sendAPDU(const uint8_t* apdu, uint8_t apduLength,
                          uint8_t* response, uint8_t &responseLength) = 0;

    /**
    * @brief Put the card in active ISO-DEP mode for APDU exchange.
    * @return true if a card was successfully activated, false otherwise.
    */
    virtual bool inListPassiveTarget() = 0;

    /**
     * @brief Virtual destructor.
     */
    virtual ~PN532Base() {}
};

#endif
