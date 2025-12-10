#include <Arduino.h>
#include "CryptnoxWallet.h"
#include "uECC.h"

volatile uint8_t uaid[200] = { 0xFF };

#define RESPONSE_LENGTH_IN_BYTES 64
#define RANDOM_BYTES 8

/* Main NFC handler:
 * - If ISO-DEP card detected → select app, request certificate, open secure channel.
 * - Otherwise → try reading UID of simple NFC tag.
 */
bool CryptnoxWallet::processCard() {
    bool ret = false;
    /* Local response buffer */
    uint8_t getCardCertificateResponse[RESPONSE_LENGTH_IN_BYTES];
    uint8_t getCardCertificateResponseLength = sizeof(getCardCertificateResponse);

    /* Check for ISO-DEP capable target (APDU-capable card) */
    if (driver.inListPassiveTarget()) {
        /* Try selecting Cryptnox app */
        if (selectApdu()) {
            /* Get certificate and establish secure channel */
            getCardCertificate(getCardCertificateResponse, getCardCertificateResponseLength);
            openSecureChannel();
            ret = true;
        }
    }
    else {
        /* Basic tag: read its UID */
        uint8_t uid[7];
        uint8_t uidLength;
        if (driver.readUID(uid, uidLength)) {
            Serial.print(F("Card UID: "));
            for (uint8_t i = 0; i < uidLength; i++) {
                if (uid[i] < 16) Serial.print(F("0"));
                Serial.print(uid[i], HEX);
                Serial.print(F(" "));
            }
            Serial.println();
        }
    }

    return ret;
}

/* Simple forward to PN532 driver for UID read */
bool CryptnoxWallet::readUID(uint8_t* uidBuffer, uint8_t &uidLength) {
    return driver.readUID(uidBuffer, uidLength);
}

/* Print PN532 firmware version via driver */
bool CryptnoxWallet::printPN532FirmwareVersion() {
    return driver.printFirmwareVersion();
}

/* SELECT APDU to activate Cryptnox application */
bool CryptnoxWallet::selectApdu() {
    bool ret = false;

    /* Application AID selection command */
    uint8_t selectApdu[] = {
        0x00, /* CLA  : ISO interindustry */
        0xA4, /* INS  : SELECT */
        0x04, /* P1   : Select by name */
        0x00, /* P2   : First or only occurrence */
        0x07, /* Lc   : Length of AID */
        0xA0, 0x00, 0x00, 0x10, 0x00, 0x01, 0x12  /* AID */
    };

    /* Print APDU */
    printApdu(selectApdu, sizeof(selectApdu));

    /* Response buffer on stack */
    uint8_t response[RESPONSE_LENGTH_IN_BYTES];
    uint8_t responseLength = sizeof(response);

    Serial.println(F("Sending Select APDU..."));

    /* Send SELECT command */
    if (driver.sendAPDU(selectApdu, sizeof(selectApdu), response, responseLength)) {
        ret = true;
    } else {
        Serial.println(F("APDU select failed."));
    }

    return ret;
}

/**
 * @brief Send get card certificate APDU with random challenge.
 * 
 * Generates RANDOM_BYTES random bytes and appends them to the APDU.
 * 
 * @param response Buffer to store the card response.
 * @param responseLength Input: buffer size, Output: actual response length.
 * @return true if the APDU exchange succeeded, false otherwise.
 */
bool CryptnoxWallet::getCardCertificate(uint8_t* response, uint8_t &responseLength) {
    bool ret = false;

    if (response!= NULL) {
        /* APDU template (last 8 bytes replaced by random nonce) */
        uint8_t getCardCertificateApdu[] = {
            0x80,  /* CLA */
            0xF8,  /* INS : OPEN SECURE CHANNEL */
            0x00,  /* P1 */
            0x00,  /* P2 */
            0x08,  /* Lc : 8 bytes nonce */
        };

        /* Generate 8 random bytes */
        uint8_t randomBytes[RANDOM_BYTES];
        randomSeed(analogRead(0));
        for (int i = 0; i < RANDOM_BYTES; i++) {
            randomBytes[i] = random(0, 256);
        }

        /* Final APDU = header + 8 random bytes */
        uint8_t fullApdu[sizeof(getCardCertificateApdu) + RANDOM_BYTES];
        memcpy(fullApdu, getCardCertificateApdu, sizeof(getCardCertificateApdu));
        memcpy(fullApdu + sizeof(getCardCertificateApdu), randomBytes, RANDOM_BYTES);

        /* Print APDU */
        printApdu(fullApdu, sizeof(fullApdu));

        Serial.println(F("Sending getCardCertificate APDU..."));

        /* Send APDU */
        if (driver.sendAPDU(fullApdu, sizeof(fullApdu), response, responseLength)) {
            Serial.println(F("APDU exchange successful!"));
            ret = true;
        } else {
            Serial.println(F("APDU getCardCertificate failed."));
        }
    }
    
    return ret;
}

/* Establish secure channel using ECC keypair exchange */
bool CryptnoxWallet::openSecureChannel() {
    bool ret = false;

    /* Keys allocated on stack to save global RAM */
    uint8_t privateKey[32];
    uint8_t publicKey[64];

    /* ECC setup and random generation */
    randomSeed(analogRead(0));
    uECC_set_rng(&uECC_RNG);
    const uECC_Curve_t *curve = uECC_secp256r1();

    /* Generate keypair */
    bool eccSuccess = uECC_make_key(publicKey, privateKey, curve);

    /* Abort if ECC fails */
    if (!eccSuccess) {
        Serial.println(F("ECC key generation failed."));
        return false;
    }

    /* APDU header for OPEN SECURE CHANNEL */
    uint8_t opcApduHeader[] = {
        0x80,  /* CLA */
        0x10,  /* INS : OPEN SECURE CHANNEL */
        0xFF,  /* P1 : pairing slot index */
        0x00,  /* P2 */
        0x41,  /* Lc : 1 format byte + 64 public key bytes */
        0x04   /* ECC uncompressed public key format */
    };

    /* Construct final APDU */
    uint8_t fullApdu[sizeof(opcApduHeader) + sizeof(publicKey)];
    memcpy(fullApdu, opcApduHeader, sizeof(opcApduHeader));
    memcpy(fullApdu + sizeof(opcApduHeader), publicKey, sizeof(publicKey));

    /* Response buffer */
    uint8_t response[255];
    uint8_t responseLength = sizeof(response);

    /* Print APDU */
    printApdu(fullApdu, sizeof(fullApdu));

    Serial.println(F("Sending OpenSecureChannel APDU..."));

    /* Send OPC request */
    if (driver.sendAPDU(fullApdu, sizeof(fullApdu), response, responseLength)) {
        Serial.println(F("APDU exchange successful!"));
        ret = true;
    } else {
        Serial.println(F("APDU exchange failed."));
    }

    return ret;
}

/**
 * @brief RNG callback used by the micro-ecc library.
 * 
 * Fills the provided buffer with cryptographically random bytes.
 * @param dest Pointer to the buffer to fill.
 * @param size Number of bytes to generate.
 * @return 1 on success.
 */
int CryptnoxWallet::uECC_RNG(uint8_t *dest, unsigned size) {
    for (unsigned i = 0; i < size; i++) {
        dest[i] = random(0, 256);
    }
    return 1;
}

/**
 * @brief Print an APDU in hexadecimal format to Serial for debugging.
 * 
 * Each byte is printed as 0xXX. Lines wrap every 16 bytes for readability.
 * @param apdu Pointer to the APDU byte array.
 * @param length Number of bytes in the APDU.
 * @param label Optional label to prepend (default: "APDU to send").
 */
void CryptnoxWallet::printApdu(const uint8_t* apdu, uint8_t length, const char* label) {
    Serial.print(label);
    Serial.print(F(": "));
    Serial.println();
    for (uint8_t i = 0; i < length; i++) {
        if (apdu[i] < 16) Serial.print("0");
        Serial.print("0x");
        Serial.print(apdu[i], HEX);
        Serial.print(" ");
        
        /* Wrap line every 16 bytes */
        if ((i + 1) % 16 == 0 && (i + 1) != length) Serial.println();
    }
    
    Serial.println();
}

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
void CryptnoxWallet::derivePairingKeyFromPUK(const uint8_t* puk, size_t pukLength, uint8_t* pairingKey) {

}
