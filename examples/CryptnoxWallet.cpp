#include <Arduino.h>
#include <SHA512.h>
#include <AES.h>
#include "CryptnoxWallet.h"
#include "AESLib.h"

#define RESPONSE_GETCARDCERTIFICATE_IN_BYTES    148U
#define RESPONSE_SELECT_IN_BYTES                 26U
#define RESPONSE_OPENSECURECHANNEL_IN_BYTES      34U
#define REQUEST_MUTUALLYAUTHENTICATE_IN_BYTES    69U
#define RESPONSE_MUTUALLYAUTHENTICATE_IN_BYTES   66U
#define RESPONSE_STATUS_WORDS_IN_BYTES            2U

#define OPENSECURECHANNEL_SALT_IN_BYTES            (RESPONSE_OPENSECURECHANNEL_IN_BYTES - RESPONSE_STATUS_WORDS_IN_BYTES)
#define GETCARDCERTIFICATE_IN_BYTES                (RESPONSE_GETCARDCERTIFICATE_IN_BYTES - RESPONSE_STATUS_WORDS_IN_BYTES)

#define RANDOM_BYTES                              8U
#define COMMON_PAIRING_DATA                        "Cryptnox Basic CommonPairingData"
#define CLIENT_PRIVATE_KEY_SIZE                  32U
#define CLIENT_PUBLIC_KEY_SIZE                   64U
#define CARDEPHEMERALPUBKEY_SIZE                 64U
#define AES_BLOCK_SIZE                           16U
#define AES_TEST_DATA_SIZE                       32U
#define INPUT_BUFFER_LIMIT                         (128U + 1U)
#define MAX_MAC_DATA_LEN                           (AES_BLOCK_SIZE + 2U * INPUT_BUFFER_LIMIT)

AESLib aesLib;

/* Print PN532 firmware version via driver */
/* MISRA C:2012 Rule 8.9 deviation:
   printPN532FirmwareVersion() is called externally via PN532 driver/library */
bool CryptnoxWallet::printPN532FirmwareVersion() {
    return driver.printFirmwareVersion();
}

/**
 * @brief Connect to the Cryptnox card and establish a secure channel.
 *
 * The function first detects if an ISO-DEP capable card is present, then establishes a secure channel
 * by selecting the Cryptnox application, retrieving the card certificate, performing ECDH key
 * exchange, and mutually authenticating with the card.
 *
 * @param[out] session Reference to the secure session to be populated with keys and IV.
 * @return true if the card was detected and secure channel was established successfully, false otherwise.
 */
// cppcheck-suppress unusedFunction
 bool CryptnoxWallet::connect(CW_SecureSession& session) {
    /* First, detect if an ISO-DEP capable card is present */
    if (!driver.inListPassiveTarget()) {
        return false;  /* No card detected */
    }

    /* If card is detected, establish secure channel */
    return establishSecureChannel(session);
}

/**
 * @brief Establish a secure channel with the Cryptnox card.
 *
 * Handles application selection, certificate retrieval, ECDH key exchange,
 * and mutual authentication to establish session keys.
 *
 * @param[out] session Reference to the secure session to be populated.
 * @return true if secure channel was established, false otherwise.
 */
bool CryptnoxWallet::establishSecureChannel(CW_SecureSession& session) {
    bool ret = false;

    /* Try selecting Cryptnox app */
    if (selectApdu()) {
        /* Local buffers for certificate */
        uint8_t cardCertificate[GETCARDCERTIFICATE_IN_BYTES];
        uint8_t cardCertificateLength = 0U;

        /* Get certificate and establish secure channel */
        if (getCardCertificate(cardCertificate, cardCertificateLength)) {
            uint8_t cardEphemeralPubKey[CARDEPHEMERALPUBKEY_SIZE];
            if (extractCardEphemeralKey(cardCertificate, cardEphemeralPubKey)) {
                uint8_t openSecureChannelSalt[OPENSECURECHANNEL_SALT_IN_BYTES];
                uint8_t clientPrivateKey[32];
                uint8_t clientPublicKey[64];
                const uECC_Curve_t* sessionCurve = uECC_secp256r1();
                if (openSecureChannel(openSecureChannelSalt, clientPublicKey, clientPrivateKey, sessionCurve)) {
                    if (mutuallyAuthenticate(session, openSecureChannelSalt, clientPublicKey, clientPrivateKey, sessionCurve, cardEphemeralPubKey)) {
                        serial.println(F("Secure channel established"));
                        ret = true;
                    } else {
                        serial.println(F("Mutual authentication failed"));
                    }
                } else {
                    serial.println(F("Failed to open secure channel"));
                }
            } else {
                serial.println(F("Failed to extract card ephemeral key"));
            }
        } else {
            serial.println(F("Failed to get card certificate"));
        }
    } else {
        serial.println(F("Failed to select Cryptnox application"));
    }

    return ret;
}

/**
 * @brief Disconnect from the Cryptnox card and clear the secure session.
 *
 * This function securely clears all session keys and resets the NFC reader
 * for the next card detection. Should be called when done with card operations.
 *
 * @param[in,out] session Reference to the secure session to clear.
 */
// cppcheck-suppress unusedFunction
void CryptnoxWallet::disconnect(CW_SecureSession& session) {
    /* Only clear session keys if secure channel was open */
    if (isSecureChannelOpen(session)) {
        session.clear();
    }
    
    /* Always reset reader for next card detection */
    driver.resetReader();
}

/**
 * @brief Check if the secure channel is open.
 *
 * This function checks if the secure channel has been established by verifying
 * if the session keys have been initialized (non-zero). A secure channel is
 * considered open if the AES key in the session is non-zero.
 *
 * The implementation follows the same pattern as the Python SDK, which checks
 * if the AES key exists to determine if the secure channel is open.
 *
 * @param[in] session Reference to the secure session to check.
 * @return true if the secure channel is open (session keys are initialized), false otherwise.
 */
bool CryptnoxWallet::isSecureChannelOpen(const CW_SecureSession& session) const {
    /* Check if AES key is non-zero (initialized) */
    /* If all bytes are zero, the secure channel is not open */
    for (uint8_t i = 0U; i < CW_AESKEY_SIZE; i++) {
        if (session.aesKey[i] != 0U) {
            return true;  /* At least one non-zero byte found, channel is open */
        }
    }
    return false;  /* All bytes are zero, channel is not open */
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
    uint8_t response[RESPONSE_SELECT_IN_BYTES];
    uint8_t responseLength = sizeof(response);

    serial.println(F("Sending Select APDU..."));

    /* Send SELECT command */
    if (driver.sendAPDU(selectApdu, sizeof(selectApdu), response, responseLength)) {
        if (checkStatusWord(response,responseLength, 0x90, 0x00)) {
            serial.println(F("APDU exchange successful!"));
            ret = true;
        } else {
            serial.println(F("APDU SW1/SW2 not expected. Error."));
        }
    } else {
        serial.println(F("APDU select failed."));
    }

    return ret;
}

/**
 * @brief Retrieves the card's ephemeral public key with a GET CARD CERTIFICATE APDU.
 *
 * Sends a GET CARD CERTIFICATE command to the card, validates the response,
 * and extracts the ephemeral EC P-256 public key used for ECDH in the secure channel.
 *
 * | Field                      | Size                | Description                                                               |
 * |----------------------------|---------------------|---------------------------------------------------------------------------|
 * | 'C'                        | 1 byte              | Certificate format identifier                                             |
 * | Nonce                      | 8 bytes (64 bits)   | Random challenge sent by the client                                       |
 * | Session Public Key         | 65 bytes            | Card's ephemeral EC P-256 public key for ECDH                             |
 * | ASN.1 DER Signature        | 70–72 bytes         | Signature over the previous fields using the card's permanent private key |
 * 
 * @param[out] cardEphemeralPubKey Buffer to store the 65-byte card ephemeral public key.
 * @param[in,out] cardEphemeralPubKeyLength Input: size of the buffer; Output: actual key length (65 bytes).
 * @return true if the APDU exchange and key extraction succeeded, false otherwise.
 */
bool CryptnoxWallet::getCardCertificate(uint8_t* cardCertificate, uint8_t &cardCertificateLength) {
    bool ret = false;
    uint8_t getCardCertificateResponse[RESPONSE_GETCARDCERTIFICATE_IN_BYTES];
    uint8_t getCardCertificateResponseLength = sizeof(getCardCertificateResponse);
   
    if (cardCertificate != NULL) {
        uint8_t randomBytes[RANDOM_BYTES];

        /* APDU template (last 8 bytes replaced by random nonce) */
        uint8_t getCardCertificateApdu[] = {
            0x80,  /* CLA */
            0xF8,  /* INS : GET CARD CERTIFICATE */
            0x00,  /* P1 */
            0x00,  /* P2 */
            0x08,  /* Lc : 8 bytes nonce */
        };

        /* Generate 8 random bytes */
        uECC_RNG(randomBytes, RANDOM_BYTES);

        /* Final APDU = header + 8 random bytes */
        uint8_t fullApdu[sizeof(getCardCertificateApdu) + RANDOM_BYTES];
        memcpy(fullApdu, getCardCertificateApdu, sizeof(getCardCertificateApdu));
        memcpy(fullApdu + sizeof(getCardCertificateApdu), randomBytes, RANDOM_BYTES);

        /* Print APDU */
        printApdu(fullApdu, sizeof(fullApdu));

        serial.println(F("Sending getCardCertificate APDU..."));

        /* Send APDU */
        if (driver.sendAPDU(fullApdu, sizeof(fullApdu), getCardCertificateResponse, getCardCertificateResponseLength)) {
            if (checkStatusWord(getCardCertificateResponse, getCardCertificateResponseLength, 0x90, 0x00)) {
                /* Remove status word from answer */
                cardCertificateLength = getCardCertificateResponseLength - RESPONSE_STATUS_WORDS_IN_BYTES;

                /* Copy only the useful data (the salt) into the buffer */
                memcpy(cardCertificate, getCardCertificateResponse, cardCertificateLength);

                serial.println(F("APDU exchange successful!"));    
                ret = true;
            } else {
                serial.println(F("APDU SW1/SW2 not expected. Error."));
            }
        } else {
            serial.println(F("APDU getCardCertificate failed."));
        }
    }
    
    return ret;
}

/**
 * @brief Retrieves the initial 32-byte salt from the card for starting a secure channel.
 *
 * This function sends the APDU command to the card to get the session salt, which is
 * required for the subsequent key derivation in the secure channel setup.
 *
 * @param[inout] salt Pointer to a 32-byte buffer where the card-provided salt will be stored.
 * @param[inout] clientPublicKey Buffer to store the client's generated 64-byte public key.
 * @param[inout] clientPrivateKey Buffer to store the client's generated 32-byte private key.
 * @param[in] sessionCurve Pointer to the uECC curve object used for key generation (e.g., uECC_secp256r1()).
 * @return true if the APDU exchange succeeded and the salt was retrieved, false otherwise.
 */
bool CryptnoxWallet::openSecureChannel(uint8_t* salt, uint8_t* sessionPublicKey, uint8_t* sessionPrivateKey, const uECC_Curve_t* sessionCurve) {
    bool ret = false;

    /* ECC setup and random generation */
    uECC_set_rng(&uECC_RNG);

    /* Generate keypair */
    bool eccSuccess = uECC_make_key(sessionPublicKey, sessionPrivateKey, sessionCurve);

    /* Abort if ECC fails */
    if (eccSuccess == false) {
        serial.println(F("ECC key generation failed."));
    }
    else {
        /* APDU header for OPEN SECURE CHANNEL */
        uint8_t opcApduHeader[] = {
            0x80,  /* CLA */
            0x10,  /* INS : OPEN SECURE CHANNEL */
            0x00,  /* P1 : pairing slot index */
            0x00,  /* P2 */
            0x41,  /* Lc : 1 format byte + 64 public key bytes */
            0x04   /* ECC uncompressed public key format */
        };

        /* Construct final APDU */
        uint8_t fullApdu[sizeof(opcApduHeader) + CLIENT_PUBLIC_KEY_SIZE];
        memcpy(fullApdu, opcApduHeader, sizeof(opcApduHeader));
        memcpy(fullApdu + sizeof(opcApduHeader), sessionPublicKey, CLIENT_PUBLIC_KEY_SIZE);

        /* Response buffer */
        uint8_t response[RESPONSE_OPENSECURECHANNEL_IN_BYTES];
        uint8_t responseLength = sizeof(response);

        /* Print APDU */
        printApdu(fullApdu, sizeof(fullApdu));

        serial.println(F("Sending OpenSecureChannel APDU..."));

        /* Send OPC request */
        if (driver.sendAPDU(fullApdu, sizeof(fullApdu), response, responseLength)) {
            if (checkStatusWord(response, responseLength, 0x90, 0x00)) {
                if (responseLength == RESPONSE_OPENSECURECHANNEL_IN_BYTES) {
                    /* Remove status word from answer */
                    size_t dataLength = OPENSECURECHANNEL_SALT_IN_BYTES;

                    /* Copy only the useful data (the salt) into the buffer */
                    memcpy(salt, response, dataLength);

                    serial.println(F("APDU exchange successful!"));    
                    ret = true;
                } 
                else {
                    serial.println(F("Unexpected response size."));
                }
            } else {
                serial.println(F("APDU SW1/SW2 not expected. Error."));
            }
        } else {
            serial.println(F("APDU exchange failed."));
        }
    }

    return ret;
}

/**
 * @brief Performs the ECDH-based mutual authentication step of the secure channel.
 *
 * This function computes the shared secret between the client's private key
 * and the card's ephemeral public key using the specified ECC curve.
 *
 * @param[in] salt Pointer to the 32-byte salt received from the card.
 * @param[in] clientPublicKey Pointer to the 64-byte client public key.
 * @param[in] clientPrivateKey Pointer to the 32-byte client private key.
 * @param[in] sessionCurve Pointer to the ECC curve (e.g., uECC_secp256r1()).
 * @param[in] cardEphemeralPubKey Pointer to the 65-byte card ephemeral public key ('0x04' prefix + X||Y).
 * @return true if the shared secret was successfully generated, false otherwise.
 */
bool CryptnoxWallet::mutuallyAuthenticate(CW_SecureSession& session, const uint8_t* salt, uint8_t* clientPublicKey, uint8_t* clientPrivateKey, const uECC_Curve_t* sessionCurve, uint8_t* cardEphemeralPubKey) {
    bool ret = false;
    uint8_t sharedSecret[32U] = { 0U };

    /* Generate ECDH shared secret with card ephemeral public key and client private key */
    if (uECC_shared_secret(cardEphemeralPubKey, clientPrivateKey, sharedSecret, sessionCurve) == 0) {
        serial.println(F("ECDH shared secret generation failed!"));
        ret = false;
    }
    else {
        uint8_t concat[32U + sizeof(COMMON_PAIRING_DATA) - 1U + 32U] = { 0U }; /* sharedSecret || pairingKey (- null character) || salt */
        uint8_t sha512Output[64U] = { 0U };
        size_t pairingKeyLen;
        size_t concatLen;

        serial.println(F("ECDH shared secret generated."));

        /* Concatenate sharedSecret, pairingKey, and salt */
        pairingKeyLen = sizeof(COMMON_PAIRING_DATA) - 1U; /* exclude null terminator */
        concatLen = 32U + pairingKeyLen + 32U;

        memcpy(concat, sharedSecret, 32U); /* copy sharedSecret */
        memcpy(concat + 32U, COMMON_PAIRING_DATA, pairingKeyLen); /* copy pairingKey */
        memcpy(concat + 32U + pairingKeyLen, salt, 32U); /* copy salt */

        /* Calculate SHA-512 over concatenated buffer */
        SHA512 sha;
        sha.update(concat, concatLen);
        sha.finalize(sha512Output, sizeof(sha512Output));
        serial.println(F("SHA-512 computed."));

        /* Split SHA-512 output into Kenc and Kmac */
        memcpy(session.aesKey, sha512Output, CW_AESKEY_SIZE);       /* first 32 bytes for encryption key */
        memcpy(session.macKey, sha512Output + CW_AESKEY_SIZE, CW_MACKEY_SIZE); /* last 32 bytes for MAC key */

        serial.println(F("aesKey and macKey derived."));

        /* Set shared iv and mac_iv by client and smartcard */
        uint8_t iv_opc[AES_BLOCK_SIZE] = { 0U };
        uint8_t mac_iv[AES_BLOCK_SIZE] = { 0U };
        memset(iv_opc, 0x01, AES_BLOCK_SIZE);

        /* Generate 256-bit random number */
        uint8_t RNG_data[32U] = { 0U };
        if (uECC_RNG(RNG_data, 32U) != 1) {
            serial.println(F("Unable to generate 256-bit random number."));
            return false;
        }

        /* Cipher the random number with aesKey */
        uint8_t ciphertextOPC[2U * INPUT_BUFFER_LIMIT] = { 0U };
        /* Set padding ISO/IEC 9797-1 Method 2 algorithm */
        aesLib.set_paddingmode(paddingMode::Bit);
        uint16_t cipherLength = aesLib.encrypt(reinterpret_cast<byte*>(RNG_data), sizeof(RNG_data), ciphertextOPC, session.aesKey, sizeof(session.aesKey), iv_opc);

        /* Compute MAC */
        uint8_t opcApduHeader[5U] = { 0x80, 0x11, 0x00, 0x00, cipherLength + AES_BLOCK_SIZE };
        /* MAC_apduHeader: zero padded opcApduHeader */
        uint8_t MAC_apduHeader[AES_BLOCK_SIZE] = { 0U };
        memcpy(MAC_apduHeader, opcApduHeader, sizeof(opcApduHeader));

        size_t  MAC_data_length = sizeof(MAC_apduHeader) + cipherLength;
        uint8_t MAC_data[MAX_MAC_DATA_LEN] = { 0U }; /* sizeof(MAC_apduHeader) + cipherLength = 16 + 48 */
        uint8_t ciphertextMACLong[2 * INPUT_BUFFER_LIMIT] = { 0U };
        if (MAC_data_length > sizeof(MAC_data)) {
            return false;
        } 

        /* Data to cipher: MAC_data = MAC_apduHeader (zero padded opcApduHeader to equal AES_BLOCK_SIZE) || ciphertextOPC */
        memcpy(MAC_data, MAC_apduHeader, sizeof(MAC_apduHeader));
        memcpy(MAC_data + sizeof(MAC_apduHeader), ciphertextOPC, cipherLength);
        /* Set no padding */
        aesLib.set_paddingmode(paddingMode::Null);
        uint16_t encryptedLengthMAC = aesLib.encrypt(reinterpret_cast<byte*>(MAC_data), MAC_data_length, ciphertextMACLong, session.macKey, sizeof(session.macKey), mac_iv);

        uint8_t MAC_value[AES_BLOCK_SIZE] = { 0U };
        /* In AES CBC-MAC last block is MAC */
        uint8_t macOffset = encryptedLengthMAC - AES_BLOCK_SIZE;
        memcpy(MAC_value, ciphertextMACLong + macOffset, AES_BLOCK_SIZE);

        /* Forge APDU: OPC HEADER || MAC_value || ciphertextOPC
           REQUEST_MUTUALLYAUTHENTICATE_IN_BYTES : apduOpcLength = sizeof(opcApduHeader) + sizeof(MAC_value) + cipherLength */
        uint8_t sendApduOpc[REQUEST_MUTUALLYAUTHENTICATE_IN_BYTES] = { 0U };
        uint16_t offset = 0U;
        memcpy(sendApduOpc + offset, opcApduHeader, sizeof(opcApduHeader));
        offset += sizeof(opcApduHeader);
        memcpy(sendApduOpc + offset, MAC_value, sizeof(MAC_value));
        offset += sizeof(MAC_value);
        memcpy(sendApduOpc + offset, ciphertextOPC, cipherLength);

        /* Send APDU */
        uint8_t response[255U] = { 0U };
        uint8_t responseLength = sizeof(response);
        if (driver.sendAPDU(sendApduOpc, sizeof(sendApduOpc), response, responseLength)) {
            if (checkStatusWord(response, responseLength, 0x90, 0x00)) {
                if (responseLength == RESPONSE_MUTUALLYAUTHENTICATE_IN_BYTES) {
                    serial.println(F("OpenSecureChannel success."));

                    /* Rolling IVs: It is the last MAC, ie the first AES_BLOCK_SIZE bytes from the last answer */
                    memcpy(session.iv, response, CW_IV_SIZE);
                    ret = true; 
                } 
                else {
                    serial.println(F("Unexpected response size."));
                }
            } else {
                serial.println(F("APDU SW1/SW2 not expected. Error."));
            }
        } else {
            serial.println(F("APDU exchange failed."));
        }

        /* Secure cleanup */
        memset(sharedSecret, 0U, sizeof(sharedSecret));
        memset(sha512Output, 0U, sizeof(sha512Output));
        memset(concat, 0U, sizeof(concat));
        memset(RNG_data, 0U, sizeof(RNG_data));
        memset(ciphertextOPC, 0U, sizeof(ciphertextOPC));
        memset(MAC_data, 0U, sizeof(MAC_data));
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
    int ret = 0;

    if ((dest != NULL) && (size > 0U)) {
        /* Seed the RNG once; ideally done once in setup() */
        static bool seeded = false;
        if (seeded == false) {
            randomSeed(analogRead(0U));
            seeded = true;
        }

        for (uint16_t i = 0U; i < size; i++) {
            dest[i] = (uint8_t)random(0U, 256U);
        }

        ret = 1;
    }

    return ret;
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
    serial.print(label);
    serial.print(F(": "));
    serial.println();
    for (uint8_t i = 0U; i < length; i++) {
        serial.print("0x");
        if (apdu[i] < 16U) serial.print("0");
        serial.print(apdu[i], HEX);
        serial.print(" ");
        
        /* Wrap line every 16 bytes */
        if ((i + 1U) % 16 == 0 && (i + 1U) != length) serial.println();
    }
    
    serial.println();
}

/**
 * @brief Checks the status word (SW1/SW2) at the end of an APDU response.
 * 
 * @param response        Pointer to the APDU response buffer.
 * @param responseLength  Actual length of the response buffer.
 * @param sw1Expected     Expected value for SW1 (e.g., 0x90).
 * @param sw2Expected     Expected value for SW2 (e.g., 0x00).
 * @return true if the last two bytes match SW1/SW2, false otherwise.
 */
bool CryptnoxWallet::checkStatusWord(const uint8_t* response, uint8_t responseLength, uint8_t sw1Expected, uint8_t sw2Expected) {
    bool ret = false;

    if ((response == NULL) || (responseLength < 2U)) {
        serial.println(F("checkStatusWord: response too short."));
        ret = false;
    }
    else {
        uint8_t sw1 = response[responseLength - 2U];
        uint8_t sw2 = response[responseLength - 1U];

        serial.print(F("Received SW1/SW2: "));
        serial.print(F("0x"));
        if (sw1 < 16) serial.print("0");
        serial.print(sw1, HEX);
        serial.print(F(" "));
        serial.print(F("0x"));
        if (sw2 < 16) serial.print("0");
        serial.println(sw2, HEX);

        if ((sw1 == sw1Expected) && (sw2 == sw2Expected)) {
            ret = true;
        }
        else {
            ret = false;
        }
    }

    return ret;
}

/**
 * @brief Extracts the card's ephemeral EC P-256 public key from the certificate.
 *
 * Certificate layout (0-based):
 * | Field                   | Size        | Offset |
 * |-------------------------|-------------|--------|
 * | 'C'                     | 1 byte      | 0      |
 * | Nonce                   | 8 bytes     | 1–8    |
 * | Session Public Key      | 65 bytes    | 9–73   |
 * | ASN.1 DER Signature     | 70–72 bytes | 74+    |
 *
 * @param[in]  cardCertificate        Pointer to the full card certificate response.
 * @param[out] cardEphemeralPubKey    Buffer to store **64 bytes** (X||Y coordinates only, no 0x04 prefix)
 *                                    for use with uECC_shared_secret. Must be at least 64 bytes.
 * @param[out] fullEphemeralPubKey65  Optional buffer to store **65 bytes** including the 0x04 prefix.
 *                                    Can be nullptr if not needed.
 */
bool CryptnoxWallet::extractCardEphemeralKey(const uint8_t* cardCertificate, uint8_t* cardEphemeralPubKey, uint8_t* fullEphemeralPubKey65) {
    bool ret = false;

    serial.print(F("Full Ephemeral Public Key (65 bytes):"));
    serial.println();
    if ((cardCertificate == NULL) || (cardEphemeralPubKey == NULL)) {
        ret = false;
    }
    else {
        const uint8_t keyStart = 1U + 8U; /* skip 'C' and nonce */
        const uint8_t fullKeyLength = 65U; /* includes 0x04 prefix */
        uint8_t i;

        for (i = 0U; i < fullKeyLength; i++) {
            uint8_t b = cardCertificate[keyStart + i];

            /* Copy full key including prefix if buffer provided */
            if (fullEphemeralPubKey65 != NULL) {
                fullEphemeralPubKey65[i] = b;
            }

            /* Skip the first byte (0x04 prefix) for ECDH */
            if (i > 0U) {
                cardEphemeralPubKey[i - 1U] = b;
            }

            /* Print hex to Serial for debugging */
            serial.print("0x");
            if (b < 0x10U) {
                serial.print('0');
            }
            serial.print(b, HEX);
            serial.print(' ');

            /* Wrap line every 16 bytes */
            if ((i + 1U) % 16 == 0 && (i + 1U) != fullKeyLength) serial.println();
        }

        serial.println();
        ret = true;  /* Success */
    }

    return ret;
}

/**
 * @brief Verifies the PIN code on the smartcard.
 *
 * This function constructs the APDU for the "Verify PIN" command and encrypts it
 * using `aes_cbc_encrypt`.
 *
 * @param[in,out] session Reference to the secure session containing keys and IV.
 */
// cppcheck-suppress unusedFunction
void CryptnoxWallet::verifyPin(CW_SecureSession& session) {
    /* Verify secure channel is open before proceeding */
    if (!isSecureChannelOpen(session)) {
        serial.println(F("Error: Secure channel not open. Cannot verify PIN."));
        return;
    }
    
    uint8_t data[] = { 0x31, 0x32, 0x33, 0x34 }; /* PIN code 1234 */
    uint8_t apdu[] = {0x80, 0x20, 0x00, 0x00};
    aes_cbc_encrypt(session, apdu, sizeof(apdu), data, sizeof(data));
}

/**
 * @brief Sends a secured GET CARD INFO APDU to retrieve card information.
 *
 * This function sends a GET DATA APDU (INS=0xFA) to retrieve card status
 * and information from the Cryptnox card over the secure channel.
 *
 * @param[in,out] session Reference to the secure session containing keys and IV.
 */
// cppcheck-suppress unusedFunction
void CryptnoxWallet::getCardInfo(CW_SecureSession& session) {
    /* Verify secure channel is open before proceeding */
    if (!isSecureChannelOpen(session)) {
        serial.println(F("Error: Secure channel not open. Cannot get card info."));
        return;
    }
    
    uint8_t data[] = { 0x00 };  /* Empty data field */
    uint8_t apdu[] = {0x80, 0xFA, 0x00, 0x00};  /* GET DATA APDU */
    aes_cbc_encrypt(session, apdu, sizeof(apdu), data, sizeof(data));
}

/**
 * @brief Encrypts data using AES-CBC, computes a MAC, and sends the APDU to the smartcard.
 *
 * This function performs AES-CBC encryption of the given data with padding (ISO/IEC 9797-1 Method 2),
 * computes a MAC over the APDU header and encrypted payload, and constructs the final APDU to send.
 * The response IV is updated from the last APDU response.
 *
 * @param[in,out] session Reference to the secure session containing keys and IV.
 * @param[in] apdu Pointer to the APDU header bytes.
 * @param[in] apduLength Length of the APDU header.
 * @param[in] data Pointer to the plaintext data to encrypt.
 * @param[in] dataLength Length of the plaintext data.
 *
 * @note
 * - AES CBC encryption is performed with `session.aesKey` and current `session.iv`.
 * - MAC is computed with `session.macKey` using AES-CBC with no padding.
 * - `session.iv` is updated after successful APDU response for rolling IV.
 */
void CryptnoxWallet::aes_cbc_encrypt(CW_SecureSession& session, const uint8_t apdu[], uint16_t apduLength, const uint8_t data[], uint16_t dataLength) {
    uint8_t encryptedData[2 * INPUT_BUFFER_LIMIT] = { 0U };

    /* Set padding ISO/IEC 9797-1 Method 2 algorithm */
    aesLib.set_paddingmode(paddingMode::Bit);
    uint16_t encryptedLength = aesLib.encrypt(reinterpret_cast<const byte*>(data), dataLength, encryptedData, session.aesKey, sizeof(session.aesKey), session.iv);

    uint8_t macApdu[] = { encryptedLength + 16U, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    uint16_t macDataLength = apduLength + sizeof(macApdu) + encryptedLength;
    uint8_t macData[macDataLength];
    uint16_t offset = 0U;
    memcpy(macData, apdu, apduLength);
    offset += apduLength;
    memcpy(macData + offset, macApdu, sizeof(macApdu));
    offset += sizeof(macApdu);
    memcpy(macData + offset, encryptedData, encryptedLength);

    uint8_t macEncryptedData[2 * INPUT_BUFFER_LIMIT] = { 0U };
    uint8_t macIv[AES_BLOCK_SIZE] = { 0U };
    /* Set no padding */
    aesLib.set_paddingmode(paddingMode::Null);
    uint16_t macEncryptedLength = aesLib.encrypt(reinterpret_cast<byte*>(macData), macDataLength, macEncryptedData, session.macKey, sizeof(session.macKey), macIv);

    uint8_t macValue[AES_BLOCK_SIZE] = { 0U };
    /* In AES CBC-MAC last block is MAC */
    uint8_t macOffset = macEncryptedLength - AES_BLOCK_SIZE;
    memcpy(macValue, macEncryptedData + macOffset, AES_BLOCK_SIZE);

    uint8_t lengthValue[] = { encryptedLength + 16U };
    uint16_t sendApduLength = apduLength + sizeof(lengthValue) + sizeof(macValue) + encryptedLength;

    uint8_t sendApdu[sendApduLength];
    offset = 0U;
    memcpy(sendApdu, apdu, apduLength);
    offset += apduLength;
    memcpy(sendApdu + offset, lengthValue, sizeof(lengthValue));
    offset += sizeof(lengthValue);
    memcpy(sendApdu + offset, macValue, sizeof(macValue));
    offset += sizeof(macValue);
    memcpy(sendApdu + offset, encryptedData, encryptedLength);

    serial.println("Apdu: ");
    for (uint8_t i = 0; i < sizeof(sendApdu); i++) {
        serial.print(sendApdu[i], HEX);
        serial.print(" ");
    }
    serial.println();

    /* Send APDU */
    uint8_t response[255U] = { 0U };
    uint8_t responseLength = sizeof(response);
    if (driver.sendAPDU(sendApdu, sizeof(sendApdu), response, responseLength)) {
        if (checkStatusWord(response, responseLength, 0x90, 0x00)) {
            serial.println(F("getCardInfo success."));

            /* Rolling IVs: It is the last MAC, ie the first AES_BLOCK_SIZE bytes from the last answer */
            memcpy(session.iv, response, CW_IV_SIZE);

            serial.println("macValue: ");
            for (uint8_t i = 0U; i < AES_BLOCK_SIZE; i++) {
                serial.print(macValue[i], HEX);
                serial.print(" ");
            }
            serial.println();

            /* Decode response */
            aes_cbc_decrypt(session, response, responseLength, macValue);
        } else {
            serial.println(F("getCardInfo APDU SW1/SW2 not expected. Error."));
        }
    } else {
        serial.println(F("APDU exchange failed."));
    }
}

/**
 * @brief Verifies the MAC and decrypts an AES-CBC encrypted APDU response.
 *
 * This function recomputes the MAC, compares it with the received MAC 
 * to ensure integrity and decrypts the response data with last MAC
 * sent as as mac_iv.
 *
 * @param[in,out] session      Reference to the secure session containing keys and IV.
 * @param[in,out] response     Encrypted APDU response buffer.
 * @param[in]     response_len Length of the response buffer.
 * @param[out]    mac_value    MAC from last sent message.
 * @return true if MAC verification succeeds, false otherwise.
 */
bool CryptnoxWallet::aes_cbc_decrypt(CW_SecureSession& session, uint8_t *response, size_t response_len, uint8_t * mac_value) {

    /* Response = MAC || cipherText || SW1/2 */
    uint8_t rep_mac[AES_BLOCK_SIZE];
    memcpy(rep_mac, response, AES_BLOCK_SIZE);
    uint8_t *rep_data = response + 16U;
    size_t cipherTextLen = response_len - 2U; /* Remove SW1/SW2 */
    if (mac_value == NULL) {
        return false;
    }

    /* Compute the MAC and compare it against received one */
    /* sizeof packet (cipherTextLen) || zero padding 15 * 0 || rep_data */
    uint8_t mac_datar[32U] = { 0U };
    mac_datar[0] = (cipherTextLen & 0xFF);
    memcpy(mac_datar + 16U, rep_data, AES_BLOCK_SIZE);

    uint8_t macEncryptedData[2 * INPUT_BUFFER_LIMIT] = { 0U };
    uint8_t mac_iv[AES_BLOCK_SIZE] = { 0U }; /* Default MAC IVs */
    /* Set no padding */
    aesLib.set_paddingmode(paddingMode::Null);
    uint16_t macEncryptedLength = aesLib.encrypt(reinterpret_cast<byte*>(mac_datar), cipherTextLen, macEncryptedData, session.macKey, sizeof(session.macKey), mac_iv);

    uint8_t recomputedMacValue[AES_BLOCK_SIZE] = { 0U };
    /* In AES CBC-MAC last block is MAC */
    uint8_t macOffset = macEncryptedLength - AES_BLOCK_SIZE;
    memcpy(recomputedMacValue, macEncryptedData + macOffset, AES_BLOCK_SIZE);

    /* Compare received MAC with computed MAC */
    if (memcmp(rep_mac, recomputedMacValue, AES_BLOCK_SIZE) == 0U) {
        serial.println(F("MACs match"));
    } else {
        serial.println(F("MAC mismatch"));
        return false;
    }

    /* Decrypt */
    uint8_t decryptedData[2 * INPUT_BUFFER_LIMIT] = { 0U };
    /* Set padding ISO/IEC 9797-1 Method 2 algorithm */
    aesLib.set_paddingmode(paddingMode::Bit);
    /* Decode the payload using the AES key and IVs corresponding to the last MAC received by the smartcard */
    uint16_t decryptedDataLength = aesLib.decrypt(rep_data, AES_BLOCK_SIZE, decryptedData, session.aesKey, sizeof(session.aesKey), mac_value);

    serial.println("Decoded data: ");
    for (uint8_t i = 0; i < decryptedDataLength; i++) {
        serial.print(decryptedData[i], HEX);
        serial.print(" ");
    }
    serial.println();

    return true;
}