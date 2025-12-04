/**
 * @file main.ino
 * @brief Arduino sketch for interacting with PN532 NFC module via I2C.
 * 
 * This code initializes the PN532 module, reads its firmware version,
 * selects an application on a card via APDU, and retrieves a random
 * 8-byte certificate from the card. It supports both ISO-DEP and MIFARE/NTAG cards.
 */

#include <Arduino.h>
#include "PN532I2C.h"

/** @brief I2C SDA pin used for PN532 communication */
#define SDA_PIN A4 

/** @brief I2C SCL pin used for PN532 communication */
#define SCL_PIN A5 

/** @brief Length of the response buffer in bytes */
#define RESPONSE_LENGHT_IN_BYTES    64

/** @brief Number of random bytes to generate for card certificate */
#define RANDOM_BYTES    8  

/**
 * @brief Pointer to the PN532 NFC/RFID interface.
 * 
 * Uses the abstract base class PN532Base to allow swapping interfaces easily.
 */
PN532Base* nfc = new PN532I2C(SDA_PIN, SCL_PIN);

/**
 * @brief Arduino setup function.
 * 
 * Initializes serial communication, starts the PN532 module,
 * and reads its firmware version. If the PN532 module fails to
 * initialize, the program halts in an infinite loop.
 */
void setup() {
    Serial.begin(115200);

    /** 
     * @brief Initialize the PN532 module.
     */
    if (!nfc->begin()) {
        Serial.println("Failed to start PN532!");
        while (1);
    }

    /** 
     * @brief Read and print the PN532 firmware version.
     */
    uint32_t fw;
    if (nfc->getFirmwareVersion(fw)) {
        Serial.print("PN532 Firmware: 0x");
        Serial.println(fw, HEX);
        Serial.print("Version: ");
        Serial.print((fw >> 16) & 0xFF); // IC version
        Serial.print(".");
        Serial.print((fw >> 8) & 0xFF);  // version rev
        Serial.print(".");
        Serial.println(fw & 0xFF);       // revision
    }
}

/**
 * @brief Sends a SELECT APDU to the NFC card to select a specific application.
 * 
 * This function constructs a standard ISO/IEC 7816-4 SELECT APDU
 * with a predefined Application Identifier (AID), sends it to the card,
 * and optionally prints the response.
 * 
 * @return true if the APDU exchange succeeded, false otherwise.
 */
bool selectApdu() {
    bool ret = false;

    uint8_t selectApdu[] = { 
        0x00,       /**< CLA: Instruction class */
        0xA4,       /**< INS: SELECT command */
        0x04,       /**< P1: Select by AID */
        0x00,       /**< P2: First or only occurrence */
        0x07,       /**< Lc: Length of the data (7 bytes for AID) */
        0xA0, 0x00, 0x00, 0x10, 0x00, 0x01, 0x12 /**< Data: AID of the application */
    };
    uint8_t response[RESPONSE_LENGHT_IN_BYTES];
    uint8_t responseLength = sizeof(response);

    Serial.println("Sending APDU...");

    if (nfc->sendAPDU(selectApdu, sizeof(selectApdu), response, responseLength)) {
        ret = true;
    } else {
        Serial.println("APDU exchange failed!");
    }

    return ret;
}

/**
 * @brief Sends a GET CARD CERTIFICATE APDU to the NFC card.
 * 
 * This function generates RANDOM_BYTES random bytes, constructs
 * the APDU, sends it to the card, and optionally prints the APDU
 * and response for verification.
 * 
 * @return true if the APDU exchange succeeded, false otherwise.
 */
bool getCardCertificate() {
    bool ret = false;

    uint8_t getCardCertificateApdu[] = { 
        0x80,       /**< CLA: Instruction class */
        0xF8,       /**< INS: Proprietary command (example) */
        0x00,       /**< P1 */
        0x00,       /**< P2 */
        0x08,       /**< Lc: Length of the data (8 bytes for random bytes) */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 /* Data: RANDOM_BYTES random bytes */
    };

    uint8_t response[RESPONSE_LENGHT_IN_BYTES];
    uint8_t responseLength = sizeof(response);

    /** @brief Initialize random generator */
    randomSeed(analogRead(0));

    /** @brief Replace the last RANDOM_BYTES bytes with random values */
    for (int i = sizeof(getCardCertificateApdu) - RANDOM_BYTES; i < sizeof(getCardCertificateApdu); i++) {
        getCardCertificateApdu[i] = random(0, 256); /**< Random value 0-255 */
    }

    /** @brief Print APDU for verification */
    Serial.print("APDU to send: ");
    for (int i = 0; i < sizeof(getCardCertificateApdu); i++) {
        if (getCardCertificateApdu[i] < 16) Serial.print("0");
        Serial.print(getCardCertificateApdu[i], HEX);
        Serial.print(" ");
    }
    Serial.println();

    Serial.println("Sending APDU...");

    if (nfc->sendAPDU(getCardCertificateApdu, sizeof(getCardCertificateApdu), response, responseLength)) {
        Serial.println("APDU exchange successful!");
        ret = true;
    } else {
        Serial.println("APDU exchange failed!");
    }

    return ret;
}

/**
 * @brief Arduino main loop function.
 * 
 * Continuously checks for NFC cards. If an ISO-DEP card is detected,
 * it sends the selectApdu() and getCardCertificate() commands.
 * If a fallback MIFARE/NTAG card is detected, it reads and prints
 * the UID to Serial.
 */
void loop() {
    uint8_t uid[7];
    uint8_t uidLength;

    if (nfc->inListPassiveTarget()) {  /**< ISO-DEP card detected */
        Serial.println("Card ISO-DEP detected, sending APDU...");
        selectApdu();
        getCardCertificate();
    } else if (nfc->readUID(uid, uidLength)) { /**< Fallback MIFARE/NTAG card */
        Serial.print("Card UID: ");
        for (int i = 0; i < uidLength; i++) Serial.print(uid[i], HEX);
        Serial.println();
    }

    delay(1000);
}
