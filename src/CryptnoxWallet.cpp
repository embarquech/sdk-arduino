#include <Arduino.h>
#include <SHA512.h>
#include <AES.h>
#include <trng.h>
#include "CryptnoxWallet.h"
#include "CryptnoxUtils.h"
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
#define APDU_HEADER_LEN                            (4U)    /* CLA + INS + P1 + P2 */
#define APDU_LC_LEN                                (1U)    /* Lc byte: length of the command data field */
#define MAC_APDU_LEN                               (12U)   /* Length-encoding block used in MAC computation */
#define INPUT_BUFFER_LIMIT                         (CW_USER_DATA_PAGE_SIZE)  /* Sized for writeUserData, the largest plaintext APDU payload */
#define ENC_BUF_MAX_LEN                            (INPUT_BUFFER_LIMIT + AES_BLOCK_SIZE)
#define MAX_MAC_DATA_LEN                           (APDU_HEADER_LEN + MAC_APDU_LEN + ENC_BUF_MAX_LEN)
#define SEND_APDU_MAX_LEN                          (APDU_HEADER_LEN + APDU_LC_LEN + AES_BLOCK_SIZE + ENC_BUF_MAX_LEN)

/* Enforce that CW_USER_DATA_PAGE_SIZE fits within a single PN532 APDU (255 bytes max):
 * APDU_HEADER_LEN(4) + Lc(1) + MAC(AES_BLOCK_SIZE) + encrypted(ENC_BUF_MAX_LEN) <= 255 */
static_assert(APDU_HEADER_LEN + APDU_LC_LEN + AES_BLOCK_SIZE + ENC_BUF_MAX_LEN <= 255U,
              "CW_USER_DATA_PAGE_SIZE too large for PN532 single APDU transport");

AESLib aesLib;

/* Shared static crypto scratch buffers for aes_cbc_encrypt / aes_cbc_decrypt.
 * Reuse is safe: decrypt is always called from inside encrypt AFTER encrypt's
 * large intermediate buffers are no longer needed.  Total: 709 bytes.
 *
 *   s_apduBuf : encrypt → macEncryptedData → sendApdu ;  decrypt → macEncryptedData
 *   s_macBuf  : encrypt → macData                     ;  decrypt → macInput
 *   s_dataBuf : encrypt → encryptedData               ;  decrypt → decryptedData
 */
static uint8_t s_apduBuf[SEND_APDU_MAX_LEN];  /* 245 bytes */
static uint8_t s_macBuf [MAX_MAC_DATA_LEN];   /* 240 bytes */
static uint8_t s_dataBuf[ENC_BUF_MAX_LEN];   /* 224 bytes */

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
    bool ret = false;

    /* Retry the full card activation sequence: inListPassiveTarget + delay + SELECT.
       When SELECT fails with PN532 status 0x1, the NFC link is broken and resending
       SELECT alone won't help — we must re-detect the card to reset the link. */
    for (uint8_t attempt = 0U; (attempt < CW_CONNECT_MAX_ATTEMPTS) && (ret == false); attempt++) {
        if (attempt > 0U) {
            serial.print(F("Retrying card connection (attempt "));
            serial.print((uint8_t)(attempt + 1U));
            serial.println(F(")..."));
            /* Reset the NFC field before retrying to give the card a clean start */
            driver.resetReader();
            delay(200);
        }

        /* Detect if an ISO-DEP capable card is present */
        if (driver.inListPassiveTarget()) {
            /* Allow the card to settle after ISO-14443-4 activation (RATS/ATS).
               Some ISO-DEP smartcards need time before accepting the first APDU. */
            delay(200);

            /* Try to establish secure channel (includes SELECT) */
            if (establishSecureChannel(session)) {
                ret = true;
            }
        }
    }

    return ret;
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
                uint8_t clientPrivateKey[CLIENT_PRIVATE_KEY_SIZE];
                uint8_t clientPublicKey[CLIENT_PUBLIC_KEY_SIZE];
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
    /* Constant-time check: OR all bytes together so every byte is always visited,
     * preventing timing side-channels that would reveal which byte is non-zero. */
    uint8_t acc = 0U;
    for (uint8_t i = 0U; i < CW_AESKEY_SIZE; i++) {
        acc |= session.aesKey[i];
    }
    return (acc != 0U);
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
        if (checkStatusWord(response, responseLength, 0x90, 0x00)) {
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
        CryptnoxUtils::uECC_rng_callback(randomBytes, RANDOM_BYTES);

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
    uECC_set_rng(&CryptnoxUtils::uECC_rng_callback);

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
                    /* Copy only the useful data (the salt) into the buffer */
                    memcpy(salt, response, OPENSECURECHANNEL_SALT_IN_BYTES);

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
        // cppcheck-suppress misra-config
        if (CryptnoxUtils::uECC_rng_callback(RNG_data, sizeof(RNG_data)) != 1) {
            serial.println(F("Unable to generate 256-bit random number."));
            return false;
        }

        /* Cipher the random number with aesKey */
        uint8_t ciphertextOPC[48U] = { 0U }; /* encrypt(RNG_data[32]) with Bit padding: ceil((32+1)/16)*16 = 48 bytes */
        /* Set padding ISO/IEC 9797-1 Method 2 algorithm */
        aesLib.set_paddingmode(paddingMode::Bit);
        uint16_t cipherLength = aesLib.encrypt(reinterpret_cast<byte*>(RNG_data), sizeof(RNG_data), ciphertextOPC, session.aesKey, sizeof(session.aesKey), iv_opc);

        /* Compute MAC */
        uint8_t opcApduHeader[APDU_HEADER_LEN + APDU_LC_LEN] = { 0x80, 0x11, 0x00, 0x00, cipherLength + AES_BLOCK_SIZE };
        /* MAC_apduHeader: zero padded opcApduHeader */
        uint8_t MAC_apduHeader[AES_BLOCK_SIZE] = { 0U };
        memcpy(MAC_apduHeader, opcApduHeader, sizeof(opcApduHeader));

        size_t  MAC_data_length = sizeof(MAC_apduHeader) + cipherLength;
        uint8_t MAC_data[64U] = { 0U };          /* MAC_apduHeader(16) + ciphertextOPC(48) = 64 bytes */
        uint8_t ciphertextMACLong[64U] = { 0U }; /* encrypt(MAC_data[64]) with Null padding = 64 bytes */
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
        /* Initialize the hardware TRNG once */
        static bool initialized = false;
        if (initialized == false) {
            TRNG.begin();
            initialized = true;
        }

        if (TRNG.fillRandom(dest, size)) {
            ret = 1;
        } else {
            Serial.println(F("TRNG.fillRandom failed"));
        }
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
 * Sends the VERIFY PIN APDU (INS=0x20) with the provided PIN over the
 * secure channel. The PIN must be 4–9 ASCII digit characters.
 *
 * @param[in,out] session   Reference to the secure session containing keys and IV.
 * @param[in]     pin       Pointer to the PIN bytes (ASCII digits, e.g. "000000000").
 * @param[in]     pinLength Length of the PIN in bytes (CW_MIN_PIN_LENGTH..CW_MAX_PIN_LENGTH).
 */
// cppcheck-suppress unusedFunction
void CryptnoxWallet::verifyPin(CW_SecureSession& session, const uint8_t* pin, uint8_t pinLength) {
    /* Verify secure channel is open before proceeding */
    if (!isSecureChannelOpen(session)) {
        serial.println(F("Error: Secure channel not open. Cannot verify PIN."));
    }
    else if ((pin == NULL) || (pinLength < CW_MIN_PIN_LENGTH) || (pinLength > CW_MAX_PIN_LENGTH)) {
        serial.println(F("Error: Invalid PIN (must be 4-9 digits)."));
    }
    else {
        /* Python SDK valid_pin() always pads PIN to CW_MAX_PIN_LENGTH (9) bytes with null bytes.
         * The card expects a fixed-length PIN field in the APDU payload. */
        uint8_t paddedPin[CW_MAX_PIN_LENGTH] = {0U};
        memcpy(paddedPin, pin, pinLength);
        uint8_t apdu[] = {0x80, 0x20, 0x00, 0x00};
        aes_cbc_encrypt(session, apdu, sizeof(apdu), paddedPin, CW_MAX_PIN_LENGTH);
    }
}

/**
 * @brief Writes data to a user memory slot, paginating in CW_USER_DATA_PAGE_SIZE pages.
 *
 * Splits data into chunks of at most CW_USER_DATA_PAGE_SIZE (1200) bytes.
 * Each chunk is sent as a separate WRITE USER DATA APDU (INS=0xFC) over the
 * secure channel with AES-CBC encryption.
 *
 * APDU: CLA=0x80, INS=0xFC, P1=slot, P2=page index (0-based)
 * Data: up to CW_USER_DATA_PAGE_SIZE bytes of plaintext per page
 *
 * @param[in,out] session    Reference to the secure session containing keys and IV.
 * @param[in]     slot       User data slot index (0-based).
 * @param[in]     data       Pointer to the data to write.
 * @param[in]     dataLength Total number of bytes to write.
 * @return true if all pages were written successfully, false otherwise.
 */
// cppcheck-suppress unusedFunction
bool CryptnoxWallet::writeUserData(CW_SecureSession& session, uint8_t slot,
                                    const uint8_t* data, uint16_t dataLength) {
    bool ret = false;

    if (!isSecureChannelOpen(session)) {
        serial.println(F("Error: Secure channel not open. Cannot write user data."));
    }
    else if ((data == NULL) || (dataLength == 0U)) {
        serial.println(F("Error: Invalid data for write user data."));
    }
    else {
        uint16_t offset = 0U;
        uint8_t  page   = 0U;
        ret = true;

        while ((offset < dataLength) && ret) {
            uint16_t chunkSize = dataLength - offset;
            if (chunkSize > CW_USER_DATA_PAGE_SIZE) {
                chunkSize = CW_USER_DATA_PAGE_SIZE;
            }

            /* WRITE USER DATA: CLA=0x80, INS=0xFC, P1=slot, P2=page index */
            uint8_t apdu[] = {0x80U, 0xFCU, slot, page};

            serial.print(F("Writing user data page "));
            serial.print(page);
            serial.print(F(" ("));
            serial.print(chunkSize);
            serial.println(F(" bytes)..."));

            if (!aes_cbc_encrypt(session, apdu, sizeof(apdu), data + offset, chunkSize)) {
                serial.print(F("Error: Write user data failed on page "));
                serial.println(page);
                ret = false;
            }
            else {
                offset += chunkSize;
                page++;
            }
        }
    }

    return ret;
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
 * @brief Generates a signature using the specified key and signature type.
 *
 * Constructs and sends the SIGN APDU (INS=0xC0) with the hash data.
 * The card performs signing internally and returns a DER-encoded signature,
 * which is then parsed to extract the raw (r, s) values.
 *
 * Protocol reference:
 *   APDU: [0x80, 0xC0, keyType, signatureType]
 *   Data: hash (32 bytes) [+ PIN if not pinLessMode]
 *   Response: DER signature → parsed to raw signature[64]
 *
 * @param[in] request CW_SignRequest containing session, keyType, signatureType, pin, hash.
 * @return CW_SignResult containing signature[64] and errorCode.
 */
// cppcheck-suppress unusedFunction
CW_SignResult CryptnoxWallet::sign(CW_SignRequest& request)
{
    CW_SignResult result;

    if (validateSignRequest(request, result)) {
        uint8_t data[CW_HASH_SIZE + CW_MAX_DERIVE_PATH_LENGTH + CW_MAX_PIN_LENGTH] = {0U};
        uint16_t dataLength = 0U;

        buildSignPayload(request, data, dataLength);

        uint8_t derResponse[255U] = {0U}; /* APDU response ≤ 255 bytes; decrypted payload ≤ 255 bytes */
        uint16_t derLength = 0U;

        if (sendSignApdu(request, data, dataLength, derResponse, derLength, result)) {
            if (extractRawSignature(derResponse, derLength, result)) {
                debugPrintSignature(result.signature);
                result.errorCode = CW_OK;
            }
        }
    }

    return result;
}

/**
 * @brief Validates the sign request parameters.
 *
 * Checks that the secure channel is open, hash is valid, PIN-less mode
 * constraints are met, and PIN length is acceptable.
 *
 * @param[in]  request  The sign request to validate.
 * @param[out] result   Populated with error code on failure.
 * @return true if the request is valid, false otherwise.
 */
bool CryptnoxWallet::validateSignRequest(const CW_SignRequest& request, CW_SignResult& result)
{
    bool ret = false;

    /* Verify secure channel is open before proceeding */
    if (!isSecureChannelOpen(request.session)) {
        serial.println(F("Error: Secure channel not open. Cannot sign."));
        result.errorCode = CW_INVALID_SESSION;
    }
    /* Validate hash parameters */
    else if ((request.hash == NULL) || (request.hashLength == 0U)) {
        serial.println(F("Error: Invalid parameters for sign."));
        result.errorCode = CW_SIGN_KEY_TOO_SHORT;
    }
    else if (request.hashLength > CW_HASH_SIZE) {
        serial.println(F("Error: Hash too large."));
        result.errorCode = CW_SIGN_KEY_TOO_SHORT;
    }
    /* Validate PIN-less mode constraints: PIN-less only allowed with k1 key types */
    else if ((request.pinLessMode) && (request.keyType != CW_SIGN_PINLESS_K1)) {
        serial.println(F("Error: PIN-less mode requires CW_SIGN_PINLESS_K1 key type."));
        result.errorCode = CW_SIGN_KEY_TOO_SHORT_WITH_PINLESS_MODE;
    }
    else {
        ret = true;

        /* Validate PIN length if not in PIN-less mode */
        if (!request.pinLessMode) {
            uint8_t pinLength = 0U;
            for (uint8_t i = 0U; i < CW_MAX_PIN_LENGTH; i++) {
                if (request.pin[i] == 0U) {
                    break;
                }
                pinLength++;
            }
            /* PIN must be 6-9 digits if provided */
            if ((pinLength > 0U) && (pinLength < CW_MIN_PIN_LENGTH)) {
                serial.println(F("Error: PIN too short (must be 6-9 digits)."));
                result.errorCode = CW_SIGN_PIN_INCORRECT;
                ret = false;
            }
        }
    }

    return ret;
}

/**
 * @brief Builds the data payload for the SIGN APDU (hash [+ BIP32 path] + optional PIN).
 *
 * For CW_SIGN_DERIVE_K1/R1 modes, the path bytes are inserted between the hash and
 * the PIN, matching the Python SDK sign(derivation=DERIVE) APDU structure.
 *
 * @param[in]  request     The sign request containing hash, derivePath and PIN data.
 * @param[out] data        Buffer to receive the payload (must be CW_HASH_SIZE + CW_MAX_DERIVE_PATH_LENGTH + CW_MAX_PIN_LENGTH bytes).
 * @param[out] dataLength  Actual payload length written.
 */
void CryptnoxWallet::buildSignPayload(const CW_SignRequest& request, uint8_t* data, uint16_t& dataLength)
{
    dataLength = request.hashLength;
    memcpy(data, request.hash, request.hashLength);

    /* For derive modes, append BIP32 path after hash */
    if ((request.keyType == CW_SIGN_DERIVE_K1 || request.keyType == CW_SIGN_DERIVE_R1) &&
        (request.derivePath != NULL) && (request.derivePathLength > 0U)) {
        memcpy(data + dataLength, request.derivePath, request.derivePathLength);
        dataLength += request.derivePathLength;
    }

    /* Append PIN if not in PIN-less mode */
    if (!request.pinLessMode) {
        uint8_t pinLength = 0U;
        for (uint8_t i = 0U; i < CW_MAX_PIN_LENGTH; i++) {
            if (request.pin[i] == 0U) {
                break;
            }
            pinLength++;
        }
        if (pinLength > 0U) {
            /* PIN must be padded to CW_MAX_PIN_LENGTH (9) bytes with null bytes,
             * matching Python SDK valid_pin() which always returns a 9-byte padded string.
             * request.pin is zero-initialized, so bytes beyond pinLength are already 0x00. */
            memcpy(data + dataLength, request.pin, CW_MAX_PIN_LENGTH);
            dataLength += CW_MAX_PIN_LENGTH;
        }
    }
}

/**
 * @brief Sends the encrypted SIGN APDU and retrieves the DER-encoded response.
 *
 * @param[in]  request      The sign request (session, keyType, signatureType).
 * @param[in]  data         Payload data (hash + optional PIN).
 * @param[in]  dataLength   Length of the payload.
 * @param[out] derResponse  Buffer to receive the decrypted DER response.
 * @param[out] derLength    Actual DER response length.
 * @param[out] result       Populated with error code on failure.
 * @return true on success, false otherwise.
 */
bool CryptnoxWallet::sendSignApdu(CW_SignRequest& request, const uint8_t* data, uint16_t dataLength,
                                   uint8_t* derResponse, uint16_t& derLength, CW_SignResult& result)
{
    bool ret = false;

    /* Build SIGN APDU header: CLA=0x80, INS=0xC0, P1=keyType, P2=signatureType */
    uint8_t apdu[] = {0x80, 0xC0, request.keyType, request.signatureType};

    serial.println(F("Sending SIGN APDU..."));

    if (aes_cbc_encrypt(request.session, apdu, sizeof(apdu), data, dataLength,
                         derResponse, &derLength)) {
        ret = true;
    }
    else {
        serial.println(F("Sign APDU failed."));
        result.errorCode = CW_SIGN_NO_KEY_LOADED;
    }

    return ret;
}

/**
 * @brief Extracts the raw (r, s) signature from a DER-encoded ECDSA response.
 *
 * Validates DER structure, parses r and s integers, strips ASN.1 leading
 * zero padding, and writes the fixed 64-byte raw signature into result.
 *
 * @param[in]  derResponse  DER-encoded signature bytes.
 * @param[in]  derLength    Length of the DER data.
 * @param[out] result       Populated with signature[64] on success, error code on failure.
 * @return true on success, false otherwise.
 */
bool CryptnoxWallet::extractRawSignature(const uint8_t* derResponse, uint16_t derLength, CW_SignResult& result)
{
    bool ret = false;

    /* Validate DER signature format (first byte must be SEQUENCE tag) */
    if ((derLength < 2U) || (derResponse[0] != CW_DER_TAG_SEQUENCE)) {
        serial.println(F("Error: Invalid signature data (missing DER SEQUENCE tag)."));
        result.errorCode = CW_NOK;
    }
    else {
        /* Extract actual DER signature length from the DER header */
        /* DER: 0x30 [total_content_length] 0x02 [r_len] [r] 0x02 [s_len] [s] */
        uint8_t derContentLength = derResponse[1];
        uint8_t derTotalLength = 2U + derContentLength;  /* tag + length byte + content */

        if (derTotalLength > derLength) {
            serial.println(F("Error: DER signature length exceeds response."));
            result.errorCode = CW_NOK;
        }
        else {
            /* Parse DER to extract raw r and s values */
            uint8_t r[33U] = {0U};
            uint8_t s[33U] = {0U};
            uint8_t rLen = 0U;
            uint8_t sLen = 0U;

            if (!parseDerSignature(derResponse, derTotalLength, r, rLen, s, sLen)) {
                serial.println(F("Error: Failed to parse DER signature."));
                result.errorCode = CW_NOK;
            }
            else {
                /* Convert to fixed 32-byte r and s (strip leading zero if present, pad if short) */
                memset(result.signature, 0U, CW_RAW_SIGNATURE_SIZE);

                /* Copy r into first 32 bytes (right-aligned) */
                if (rLen > 0U) {
                    uint8_t rSrc = 0U;
                    uint8_t rDstLen = 32U;
                    /* Strip leading zero byte (ASN.1 sign padding) */
                    if ((rLen == 33U) && (r[0] == 0x00U)) {
                        rSrc = 1U;
                        rLen = 32U;
                    }
                    if (rLen <= rDstLen) {
                        memcpy(result.signature + (rDstLen - rLen), r + rSrc, rLen);
                    }
                }

                /* Copy s into last 32 bytes (right-aligned) */
                if (sLen > 0U) {
                    uint8_t sSrc = 0U;
                    uint8_t sDstLen = 32U;
                    /* Strip leading zero byte (ASN.1 sign padding) */
                    if ((sLen == 33U) && (s[0] == 0x00U)) {
                        sSrc = 1U;
                        sLen = 32U;
                    }
                    if (sLen <= sDstLen) {
                        memcpy(result.signature + 32U + (sDstLen - sLen), s + sSrc, sLen);
                    }
                }

                ret = true;
            }
        }
    }

    return ret;
}

/**
 * @brief Prints the raw signature bytes to serial for debugging.
 *
 * @param[in] signature  Pointer to CW_RAW_SIGNATURE_SIZE bytes.
 */
void CryptnoxWallet::debugPrintSignature(const uint8_t* signature)
{
    serial.print(F("Signature ("));
    serial.print((uint8_t)CW_RAW_SIGNATURE_SIZE);
    serial.println(F(" bytes):"));
    for (uint8_t i = 0U; i < CW_RAW_SIGNATURE_SIZE; i++) {
        serial.print(F("0x"));
        if (signature[i] < 0x10U) serial.print(F("0"));
        serial.print(signature[i], HEX);
        serial.print(F(" "));
        if ((i + 1U) % 16U == 0U && (i + 1U) != CW_RAW_SIGNATURE_SIZE) serial.println();
    }
    serial.println();
}

/**
 * @brief Parse a DER-encoded ECDSA signature to extract raw r and s integer values.
 *
 * DER format: 0x30 [total-length] 0x02 [r-length] [r-bytes] 0x02 [s-length] [s-bytes]
 *
 * Note: r and s may have a leading 0x00 byte if the high bit is set (ASN.1 sign encoding).
 * Callers should handle stripping this leading zero when converting to fixed-size values.
 *
 * @param[in]  der       DER-encoded signature.
 * @param[in]  derLength Length of DER data.
 * @param[out] r         Buffer for r value (at least 33 bytes).
 * @param[out] rLength   Actual r length.
 * @param[out] s         Buffer for s value (at least 33 bytes).
 * @param[out] sLength   Actual s length.
 * @return true on success, false on malformed DER.
 */
bool CryptnoxWallet::parseDerSignature(const uint8_t* der, uint8_t derLength,
                                        uint8_t* r, uint8_t& rLength,
                                        uint8_t* s, uint8_t& sLength) {
    bool ret = false;

    if ((der == NULL) || (derLength < 6U) || (r == NULL) || (s == NULL)) {
        /* Invalid parameters */
    }
    /* Verify SEQUENCE tag */
    else if (der[0] != CW_DER_TAG_SEQUENCE) {
        /* Missing DER SEQUENCE tag */
    }
    else {
        uint8_t pos = 2U;  /* Skip SEQUENCE tag and length */

        /* Read r: INTEGER tag + length + value */
        /* Note: pos < derLength is guaranteed since derLength >= 6 and pos = 2 */
        if (der[pos] != CW_DER_TAG_INTEGER) {
            /* Missing DER INTEGER tag for r */
        }
        else {
            pos++;
            rLength = der[pos];
            pos++;
            if ((pos + rLength) > derLength) {
                /* r value exceeds DER data bounds */
            }
            else {
                memcpy(r, der + pos, rLength);
                pos += rLength;

                /* Read s: INTEGER tag + length + value */
                if ((pos >= derLength) || (der[pos] != CW_DER_TAG_INTEGER)) {
                    /* Missing DER INTEGER tag for s */
                }
                else {
                    pos++;
                    sLength = der[pos];
                    pos++;
                    if ((pos + sLength) > derLength) {
                        /* s value exceeds DER data bounds */
                    }
                    else {
                        memcpy(s, der + pos, sLength);
                        ret = true;
                    }
                }
            }
        }
    }

    return ret;
}

/**
 * @brief Encrypts data using AES-CBC, computes a MAC, and sends the APDU to the smartcard.
 *
 * This function performs AES-CBC encryption of the given data with padding (ISO/IEC 9797-1 Method 2),
 * computes a MAC over the APDU header and encrypted payload, and constructs the final APDU to send.
 * The response IV is updated from the last APDU response.
 *
 * @param[in,out] session Reference to the secure session containing keys and IV.
 * @param[in]     apdu                  Pointer to the APDU header bytes.
 * @param[in]     apduLength            Length of the APDU header.
 * @param[in]     data                  Pointer to the plaintext data to encrypt.
 * @param[in]     dataLength            Length of the plaintext data.
 * @param[out]    decryptedOutput       Optional buffer to receive decrypted response data (NULL to skip).
 * @param[out]    decryptedOutputLength Optional pointer to receive the decrypted data length (NULL to skip).
 * @return true if APDU was sent and response decoded successfully, false otherwise.
 *
 * @note
 * - AES CBC encryption is performed with `session.aesKey` and current `session.iv`.
 * - MAC is computed with `session.macKey` using AES-CBC with no padding.
 * - `session.iv` is updated after successful APDU response for rolling IV.
 */
bool CryptnoxWallet::aes_cbc_encrypt(CW_SecureSession& session, const uint8_t apdu[], uint16_t apduLength,
                                      const uint8_t data[], uint16_t dataLength,
                                      uint8_t* decryptedOutput, uint16_t* decryptedOutputLength) {
    bool ret = false;
    /* Use shared file-scope static buffers (s_apduBuf, s_macBuf, s_dataBuf).
     * s_dataBuf = encryptedData (reused as decryptedData in decrypt phase)
     * s_macBuf  = macData       (reused as macInput in decrypt phase)
     * s_apduBuf = macEncryptedData first, then reused as sendApdu; reused again in decrypt */

    /* Set padding ISO/IEC 9797-1 Method 2 algorithm */
    aesLib.set_paddingmode(paddingMode::Bit);
    uint16_t encryptedLength = aesLib.encrypt(reinterpret_cast<const byte*>(data), dataLength, s_dataBuf, session.aesKey, sizeof(session.aesKey), session.iv);

    uint16_t lcValue = encryptedLength + (uint16_t)AES_BLOCK_SIZE;
    uint8_t macApdu[MAC_APDU_LEN] = {0U};
    macApdu[0U] = (uint8_t)lcValue;
    uint16_t macDataLength = apduLength + sizeof(macApdu) + encryptedLength;
    if (macDataLength > MAX_MAC_DATA_LEN) {
        serial.println(F("Error: MAC data length exceeds buffer."));
        return false;
    }
    uint16_t offset = 0U;
    memcpy(s_macBuf, apdu, apduLength);
    offset += apduLength;
    memcpy(s_macBuf + offset, macApdu, sizeof(macApdu));
    offset += sizeof(macApdu);
    memcpy(s_macBuf + offset, s_dataBuf, encryptedLength);

    uint8_t macIv[AES_BLOCK_SIZE] = { 0U };
    /* Set no padding */
    aesLib.set_paddingmode(paddingMode::Null);
    /* s_apduBuf used first as macEncryptedData output */
    uint16_t macEncryptedLength = aesLib.encrypt(reinterpret_cast<byte*>(s_macBuf), macDataLength, s_apduBuf, session.macKey, sizeof(session.macKey), macIv);

    uint8_t macValue[AES_BLOCK_SIZE] = { 0U };
    /* In AES CBC-MAC last block is MAC */
    uint16_t macOffset = macEncryptedLength - AES_BLOCK_SIZE;
    memcpy(macValue, s_apduBuf + macOffset, AES_BLOCK_SIZE);

    const uint8_t lc = (uint8_t)lcValue;
    uint16_t sendApduLength = apduLength + APDU_LC_LEN + sizeof(macValue) + encryptedLength;
    if (sendApduLength > SEND_APDU_MAX_LEN) {
        serial.println(F("Error: Send APDU length exceeds buffer."));
        return false;
    }
    /* s_apduBuf reused as sendApdu (macEncryptedData phase is done) */
    offset = 0U;
    memcpy(s_apduBuf, apdu, apduLength);
    offset += apduLength;
    s_apduBuf[offset] = lc;
    offset += APDU_LC_LEN;
    memcpy(s_apduBuf + offset, macValue, sizeof(macValue));
    offset += sizeof(macValue);
    memcpy(s_apduBuf + offset, s_dataBuf, encryptedLength);

    serial.println("Apdu: ");
    for (uint16_t i = 0U; i < sendApduLength; i++) {
        serial.print(s_apduBuf[i], HEX);
        serial.print(" ");
    }
    serial.println();

    /* Send APDU */
    uint8_t response[255U] = { 0U };
    uint8_t responseLength = sizeof(response);
    if (driver.sendAPDU(s_apduBuf, sendApduLength, response, responseLength)) {
        if (checkStatusWord(response, responseLength, 0x90, 0x00)) {
            serial.println(F("Secured APDU success."));

            /* Rolling IVs: It is the last MAC, ie the first AES_BLOCK_SIZE bytes from the last answer */
            memcpy(session.iv, response, CW_IV_SIZE);

            serial.println(F("macValue: "));
            for (uint8_t i = 0U; i < AES_BLOCK_SIZE; i++) {
                serial.print(macValue[i], HEX);
                serial.print(F(" "));
            }
            serial.println();

            /* Decode response and optionally pass decrypted data to caller */
            ret = aes_cbc_decrypt(session, response, responseLength, macValue,
                                  decryptedOutput, decryptedOutputLength);
        } else {
            serial.println(F("Secured APDU SW1/SW2 not expected. Error."));
        }
    } else {
        serial.println(F("APDU exchange failed."));
    }

    return ret;
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
bool CryptnoxWallet::aes_cbc_decrypt(CW_SecureSession& session, uint8_t *response, size_t response_len,
                                      uint8_t* mac_value,
                                      uint8_t* decryptedOutput, uint16_t* decryptedOutputLength) {

    /* Response layout: MAC(16) || cipherText(N) || SW1(1) || SW2(1) */
    uint8_t rep_mac[AES_BLOCK_SIZE];
    memcpy(rep_mac, response, AES_BLOCK_SIZE);
    uint8_t *rep_data = response + AES_BLOCK_SIZE;
    size_t totalDataLen = response_len - 2U;            /* Remove outer SW1/SW2 */
    size_t cipherLen = totalDataLen - AES_BLOCK_SIZE;   /* Actual ciphertext length (without MAC) */

    if (mac_value == NULL || cipherLen == 0U) {
        return false;
    }

    /* --- Verify MAC (AES-CBC-MAC over [length_header(16)] || [all_ciphertext]) --- */
    /* Build MAC input: [totalDataLen & 0xFF, 0*15] || all ciphertext bytes */
    /* This matches Python SDK _decode(): data_mac_list + rep_data */
    size_t macInputLen = AES_BLOCK_SIZE + cipherLen;
    /* Use shared file-scope static buffers (s_apduBuf, s_macBuf, s_dataBuf).
     * Encrypt's large buffers are all done by the time decrypt is called, so reuse is safe.
     * s_macBuf  = macInput       (was macData in encrypt)
     * s_apduBuf = macEncryptedData (was sendApdu in encrypt)
     * s_dataBuf = decryptedData  (was encryptedData in encrypt) */
    if (macInputLen > sizeof(s_macBuf)) {
        serial.println(F("Error: Response too large for MAC verification."));
        return false;
    }

    /* First 16 bytes: length encoding + zero padding */
    memset(s_macBuf, 0U, AES_BLOCK_SIZE);   /* zero header block including bytes [1..15] */
    s_macBuf[0] = (uint8_t)totalDataLen;

    /* Append ALL ciphertext (not just first block) */
    memcpy(s_macBuf + AES_BLOCK_SIZE, rep_data, cipherLen);

    /* Compute MAC (AES-CBC-MAC with zero IV, no padding) */
    uint8_t mac_iv[AES_BLOCK_SIZE] = { 0U };
    aesLib.set_paddingmode(paddingMode::Null);
    uint16_t macEncryptedLength = aesLib.encrypt(reinterpret_cast<byte*>(s_macBuf), macInputLen, s_apduBuf, session.macKey, sizeof(session.macKey), mac_iv);

    uint8_t recomputedMacValue[AES_BLOCK_SIZE] = { 0U };
    /* In AES CBC-MAC the last block is the MAC */
    uint16_t macOffset = macEncryptedLength - AES_BLOCK_SIZE;
    memcpy(recomputedMacValue, s_apduBuf + macOffset, AES_BLOCK_SIZE);

    /* Compare received MAC with computed MAC */
    // cppcheck-suppress misra-config
    if (CryptnoxUtils::secure_compare(rep_mac, recomputedMacValue, AES_BLOCK_SIZE)) {
        serial.println(F("MACs match"));
    } else {
        serial.println(F("MAC mismatch"));
        return false;
    }

    /* --- Decrypt ALL ciphertext (not just one block) --- */
    /* Set padding ISO/IEC 9797-1 Method 2 algorithm */
    aesLib.set_paddingmode(paddingMode::Bit);
    /* Decode the full payload using the AES key and IV = last MAC sent to the card */
    /* s_dataBuf reused as decryptedData (encryptedData phase is done) */
    uint16_t decryptedDataLength = aesLib.decrypt(rep_data, cipherLen, s_dataBuf, session.aesKey, sizeof(session.aesKey), mac_value);

    bool ret = false;

    /* The decoded data contains: [payload] [SW1] [SW2]
     * Last 2 bytes are the card's inner status word (like Python SDK _decode).
     * Check both lower and upper bounds before accessing s_dataBuf. */
    if (decryptedDataLength < 2U) {
        serial.println(F("Error: Decoded data too short (missing inner SW)."));
    }
    else if (decryptedDataLength > sizeof(s_dataBuf)) {
        serial.println(F("Error: Decoded data length exceeds buffer."));
    }
    else {
        serial.println(F("Decoded data: "));
        for (uint16_t i = 0U; i < decryptedDataLength; i++) {
            serial.print(s_dataBuf[i], HEX);
            serial.print(F(" "));
        }
        serial.println();

        uint8_t innerSW1 = s_dataBuf[decryptedDataLength - 2U];
        uint8_t innerSW2 = s_dataBuf[decryptedDataLength - 1U];
        uint16_t payloadLength = decryptedDataLength - 2U;

        if ((innerSW1 != 0x90U) || (innerSW2 != 0x00U)) {
            serial.print(F("Card error SW: 0x"));
            if (innerSW1 < 0x10U) { serial.print(F("0")); }
            serial.print(innerSW1, HEX);
            serial.print(F(" 0x"));
            if (innerSW2 < 0x10U) { serial.print(F("0")); }
            serial.println(innerSW2, HEX);
        }
        else {
            ret = true;
        }

        /* Copy payload (without inner SW) to output buffer if provided */
        if ((decryptedOutput != NULL) && (decryptedOutputLength != NULL)) {
            memcpy(decryptedOutput, s_dataBuf, payloadLength);
            *decryptedOutputLength = payloadLength;
        }
    }

    return ret;
}