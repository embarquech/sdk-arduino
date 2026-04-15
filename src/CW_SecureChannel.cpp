#include "CW_SecureChannel.h"
#include "CryptnoxUtils.h"
#if CW_VERIFY_CERT
#include "CW_TrustedKeys.h"
#endif
#include "uECC.h"

/******************************************************************
 * Module-level constants
 ******************************************************************/

#define RESPONSE_GETCARDCERTIFICATE_IN_BYTES    148U
#define RESPONSE_SELECT_IN_BYTES                 26U
#define RESPONSE_OPENSECURECHANNEL_IN_BYTES      34U
#define REQUEST_MUTUALLYAUTHENTICATE_IN_BYTES    69U
#define RESPONSE_MUTUALLYAUTHENTICATE_IN_BYTES   66U
#define RESPONSE_STATUS_WORDS_IN_BYTES            2U

#define OPENSECURECHANNEL_SALT_IN_BYTES   (RESPONSE_OPENSECURECHANNEL_IN_BYTES - RESPONSE_STATUS_WORDS_IN_BYTES)
#define GETCARDCERTIFICATE_IN_BYTES       (RESPONSE_GETCARDCERTIFICATE_IN_BYTES - RESPONSE_STATUS_WORDS_IN_BYTES)

#define RANDOM_BYTES              8U
#define COMMON_PAIRING_DATA       "Cryptnox Basic CommonPairingData"
#define CLIENT_PRIVATE_KEY_SIZE  32U
#define CLIENT_PUBLIC_KEY_SIZE   64U
#define CARDEPHEMERALPUBKEY_SIZE 64U
#define AES_BLOCK_SIZE           16U
#define APDU_HEADER_LEN           (4U)
#define APDU_LC_LEN               (1U)
#define MAC_APDU_LEN             (12U)
#define INPUT_BUFFER_LIMIT        (CW_USER_DATA_PAGE_SIZE)
#define ENC_BUF_MAX_LEN           (INPUT_BUFFER_LIMIT + AES_BLOCK_SIZE)
#define MAX_MAC_DATA_LEN          (APDU_HEADER_LEN + MAC_APDU_LEN + ENC_BUF_MAX_LEN)
#define SEND_APDU_MAX_LEN         (APDU_HEADER_LEN + APDU_LC_LEN + AES_BLOCK_SIZE + ENC_BUF_MAX_LEN)

/* Enforce APDU fits within a single PN532 APDU (255 bytes max) */
static_assert(APDU_HEADER_LEN + APDU_LC_LEN + AES_BLOCK_SIZE + ENC_BUF_MAX_LEN <= 255U,
              "CW_USER_DATA_PAGE_SIZE too large for PN532 single APDU transport");

/* Shared static crypto scratch buffers.
 * Reuse is safe because aesCbcDecrypt is always called from inside aesCbcEncrypt
 * AFTER aesCbcEncrypt's large buffers are no longer needed.
 * SINGLE-THREADED ASSUMPTION: these module-level buffers are NOT re-entrant.
 * They are safe only in the single-threaded Arduino execution environment.
 * If multi-threading is ever introduced, guard each call-site with a mutex or
 * replace these with stack-allocated locals. */
static uint8_t s_apduBuf[SEND_APDU_MAX_LEN];  /* 245 bytes */
static uint8_t s_macBuf [MAX_MAC_DATA_LEN];   /* 240 bytes */
static uint8_t s_dataBuf[ENC_BUF_MAX_LEN];   /* 224 bytes */

#if CW_VERIFY_CERT
/* Manufacturer certificate assembly buffer (used only during verifyCertificateChain). */
static uint8_t s_mfCertBuf[CW_MANUF_CERT_MAX_BYTES];

/* ASN.1 / DER OID patterns used for certificate parsing.
 * K1_PUBKEY_OID  : secp256r1 SubjectPublicKeyInfo OID + BIT STRING header
 *                  "2a8648ce3d030107" (OID) + "034200" (BIT STRING tag, len 66, 0 unused bits)
 * ECDSA_SHA256_OID: ecdsa-with-SHA256 AlgorithmIdentifier OID + BIT STRING tag
 *                  "06082a8648ce3d040302" (OID) + "03" (BIT STRING tag) */
static const uint8_t K1_PUBKEY_OID[11U] = {
    0x2aU, 0x86U, 0x48U, 0xceU, 0x3dU,
    0x03U, 0x01U, 0x07U,               /* secp256r1 OID */
    0x03U, 0x42U, 0x00U                /* BIT STRING: tag, len=66, unused=0 */
};
static const uint8_t ECDSA_SHA256_OID[11U] = {
    0x06U, 0x08U,                      /* OID tag + length 8 */
    0x2aU, 0x86U, 0x48U, 0xceU, 0x3dU, 0x04U, 0x03U, 0x02U, /* ecdsa-with-SHA256 */
    0x03U                              /* BIT STRING tag */
};
#endif /* CW_VERIFY_CERT */

/******************************************************************
 * Constructor
 ******************************************************************/

CW_SecureChannel::CW_SecureChannel(CW_NfcTransport& driver,
                                   CW_Logger& logger,
                                   CW_CryptoProvider& crypto)
    : _driver(driver), _logger(logger), _crypto(crypto) {
}

/******************************************************************
 * Transport delegation methods
 ******************************************************************/

bool CW_SecureChannel::begin() {
    return _driver.begin();
}

bool CW_SecureChannel::inListPassiveTarget() {
    return _driver.inListPassiveTarget();
}

void CW_SecureChannel::resetReader() {
    _driver.resetReader();
}

bool CW_SecureChannel::printFirmwareVersion() {
    return _driver.printFirmwareVersion();
}

/******************************************************************
 * Private helpers
 ******************************************************************/

bool CW_SecureChannel::checkStatusWord(const uint8_t* response, uint8_t responseLength,
                                       uint8_t sw1Expected, uint8_t sw2Expected) {
    bool ret = false;

    if ((response == NULL) || (responseLength < 2U)) {
#if CW_DEBUG_LOGGING
        _logger.println(F("checkStatusWord: response too short."));
#endif
    }
    else {
        uint8_t sw1 = response[responseLength - 2U];
        uint8_t sw2 = response[responseLength - 1U];

        if ((sw1 == sw1Expected) && (sw2 == sw2Expected)) {
            ret = true;
        }
        else {
#if CW_DEBUG_LOGGING
            _logger.print(F("SW: 0x"));
            if (sw1 < 16U) { _logger.print(F("0")); }
            _logger.print(sw1, HEX);
            _logger.print(F(" 0x"));
            if (sw2 < 16U) { _logger.print(F("0")); }
            _logger.println(sw2, HEX);
#endif
        }
    }

    return ret;
}

/******************************************************************
 * Public methods
 ******************************************************************/

bool CW_SecureChannel::selectApdu() {
    bool ret = false;

    uint8_t selectApduCmd[] = {
        0x00, 0xA4, 0x04, 0x00,
        0x07,
        0xA0, 0x00, 0x00, 0x10, 0x00, 0x01, 0x12
    };

    uint8_t response[RESPONSE_SELECT_IN_BYTES];
    uint8_t responseLength = sizeof(response);

    if (_driver.sendAPDU(selectApduCmd, sizeof(selectApduCmd), response, responseLength)) {
        if (checkStatusWord(response, responseLength, 0x90U, 0x00U)) {
            ret = true;
        } else {
#if CW_DEBUG_LOGGING
            _logger.println(F("Select APDU failed."));
#endif
        }
    } else {
#if CW_DEBUG_LOGGING
        _logger.println(F("APDU select failed."));
#endif
    }

    return ret;
}

bool CW_SecureChannel::getCardCertificate(uint8_t* cardCertificate, uint8_t& cardCertificateLength) {
    bool ret = false;
    uint8_t getCardCertificateResponse[RESPONSE_GETCARDCERTIFICATE_IN_BYTES];
    uint8_t getCardCertificateResponseLength = sizeof(getCardCertificateResponse);

    if (cardCertificate != NULL) {
        uint8_t randomBytes[RANDOM_BYTES];
        _crypto.random(randomBytes, RANDOM_BYTES);

        /* Store nonce for replay check in verifyCertificateChain(). */
#if CW_VERIFY_CERT
        memcpy(_lastNonce, randomBytes, RANDOM_BYTES);
#endif

        uint8_t getCardCertificateApdu[] = {
            0x80, 0xF8, 0x00, 0x00, 0x08
        };

        uint8_t fullApdu[sizeof(getCardCertificateApdu) + RANDOM_BYTES];
        memcpy(fullApdu, getCardCertificateApdu, sizeof(getCardCertificateApdu));
        memcpy(fullApdu + sizeof(getCardCertificateApdu), randomBytes, RANDOM_BYTES);

        if (_driver.sendAPDU(fullApdu, sizeof(fullApdu),
                             getCardCertificateResponse, getCardCertificateResponseLength)) {
            /* Bounds check: reject oversized responses before any buffer access — H4 */
            if (getCardCertificateResponseLength > RESPONSE_GETCARDCERTIFICATE_IN_BYTES) {
#if CW_DEBUG_LOGGING
                _logger.println(F("getCardCertificate: response exceeds buffer size."));
#endif
            }
            else if (checkStatusWord(getCardCertificateResponse, getCardCertificateResponseLength,
                                0x90U, 0x00U)) {
                cardCertificateLength = getCardCertificateResponseLength - RESPONSE_STATUS_WORDS_IN_BYTES;
                CryptnoxUtils::safe_memcpy(cardCertificate, GETCARDCERTIFICATE_IN_BYTES,
                                           getCardCertificateResponse, cardCertificateLength);
                ret = true;
            } else {
#if CW_DEBUG_LOGGING
                _logger.println(F("getCardCertificate: bad SW."));
#endif
            }
        } else {
#if CW_DEBUG_LOGGING
            _logger.println(F("getCardCertificate APDU failed."));
#endif
        }
    }

    return ret;
}

bool CW_SecureChannel::extractCardEphemeralKey(const uint8_t* cardCertificate,
                                               uint8_t* cardEphemeralPubKey,
                                               uint8_t* fullEphemeralPubKey65) {
    bool ret = false;

    if ((cardCertificate == NULL) || (cardEphemeralPubKey == NULL)) {
        ret = false;
    }
    else {
        const uint8_t keyStart = 1U + 8U; /* skip 'C' and nonce */
        const uint8_t fullKeyLength = 65U;

        for (uint8_t i = 0U; i < fullKeyLength; i++) {
            uint8_t b = cardCertificate[keyStart + i];
            if (fullEphemeralPubKey65 != NULL) {
                fullEphemeralPubKey65[i] = b;
            }
            if (i > 0U) {
                cardEphemeralPubKey[i - 1U] = b;
            }
        }

        ret = true;
    }

    return ret;
}

bool CW_SecureChannel::openSecureChannel(uint8_t* salt,
                                         uint8_t* sessionPublicKey,
                                         uint8_t* sessionPrivateKey,
                                         const uECC_Curve_t* sessionCurve) {
    bool ret = false;

    if (!_crypto.makeKey(sessionPublicKey, sessionPrivateKey, sessionCurve)) {
#if CW_DEBUG_LOGGING
        _logger.println(F("ECC key generation failed."));
#endif
    }
    else {
        uint8_t opcApduHeader[] = {
            0x80, 0x10, 0x00, 0x00, 0x41, 0x04
        };

        uint8_t fullApdu[sizeof(opcApduHeader) + CLIENT_PUBLIC_KEY_SIZE];
        memcpy(fullApdu, opcApduHeader, sizeof(opcApduHeader));
        memcpy(fullApdu + sizeof(opcApduHeader), sessionPublicKey, CLIENT_PUBLIC_KEY_SIZE);

        uint8_t response[RESPONSE_OPENSECURECHANNEL_IN_BYTES];
        uint8_t responseLength = sizeof(response);

        if (_driver.sendAPDU(fullApdu, sizeof(fullApdu), response, responseLength)) {
            /* Explicit upper-bound check before any buffer access — C2 */
            if (responseLength > RESPONSE_OPENSECURECHANNEL_IN_BYTES) {
#if CW_DEBUG_LOGGING
                _logger.println(F("OpenSecureChannel: response exceeds buffer size."));
#endif
            }
            else if (checkStatusWord(response, responseLength, 0x90U, 0x00U)) {
                if (responseLength == RESPONSE_OPENSECURECHANNEL_IN_BYTES) {
                    memcpy(salt, response, OPENSECURECHANNEL_SALT_IN_BYTES);
                    ret = true;
                } else {
#if CW_DEBUG_LOGGING
                    _logger.println(F("OpenSecureChannel: unexpected response size."));
#endif
                }
            } else {
#if CW_DEBUG_LOGGING
                _logger.println(F("OpenSecureChannel: bad SW."));
#endif
            }
        } else {
#if CW_DEBUG_LOGGING
            _logger.println(F("OpenSecureChannel APDU failed."));
#endif
        }
    }

    return ret;
}

bool CW_SecureChannel::mutuallyAuthenticate(CW_SecureSession& session,
                                            const uint8_t* salt,
                                            uint8_t* clientPublicKey,
                                            uint8_t* clientPrivateKey,
                                            const uECC_Curve_t* sessionCurve,
                                            uint8_t* cardEphemeralPubKey) {
    bool ret = false;
    uint8_t sharedSecret[32U] = { 0U };

    if (!_crypto.ecdh(cardEphemeralPubKey, clientPrivateKey, sharedSecret, sessionCurve)) {
#if CW_DEBUG_LOGGING
        _logger.println(F("ECDH failed."));
#endif
    }
    else {
        uint8_t concat[32U + sizeof(COMMON_PAIRING_DATA) - 1U + 32U] = { 0U };
        uint8_t sha512Output[64U] = { 0U };
        const size_t pairingKeyLen = sizeof(COMMON_PAIRING_DATA) - 1U;
        const size_t concatLen    = 32U + pairingKeyLen + 32U;

        (void)CryptnoxUtils::safe_memcpy(concat, sizeof(concat),
                                         sharedSecret, CLIENT_PRIVATE_KEY_SIZE);
        (void)CryptnoxUtils::safe_memcpy(concat + CLIENT_PRIVATE_KEY_SIZE,
                                         sizeof(concat) - CLIENT_PRIVATE_KEY_SIZE,
                                         reinterpret_cast<const uint8_t*>(COMMON_PAIRING_DATA),
                                         pairingKeyLen);
        (void)CryptnoxUtils::safe_memcpy(concat + CLIENT_PRIVATE_KEY_SIZE + pairingKeyLen,
                                         sizeof(concat) - CLIENT_PRIVATE_KEY_SIZE - pairingKeyLen,
                                         salt, CLIENT_PRIVATE_KEY_SIZE);

        _crypto.sha512(concat, concatLen, sha512Output);

        (void)CryptnoxUtils::safe_memcpy(session.aesKey, CW_AESKEY_SIZE,
                                         sha512Output, CW_AESKEY_SIZE);
        (void)CryptnoxUtils::safe_memcpy(session.macKey, CW_MACKEY_SIZE,
                                         sha512Output + CW_AESKEY_SIZE, CW_MACKEY_SIZE);

        uint8_t iv_opc[AES_BLOCK_SIZE] = { 0U };
        uint8_t mac_iv[AES_BLOCK_SIZE] = { 0U };
        memset(iv_opc, 0x01U, AES_BLOCK_SIZE);

        uint8_t RNG_data[32U] = { 0U };
        /* cppcheck-suppress misra-config
         * MISRA-C:2012 Rule 15.5: function has more than one point of exit.
         * Early return is intentional here to immediately release sensitive
         * key material (sharedSecret, sha512Output) on RNG failure without
         * adding a deeply nested else branch. */
        if (!_crypto.random(RNG_data, sizeof(RNG_data))) {
#if CW_DEBUG_LOGGING
            _logger.println(F("RNG failed."));
#endif
            CryptnoxUtils::secure_wipe(sharedSecret, sizeof(sharedSecret));
            CryptnoxUtils::secure_wipe(sha512Output, sizeof(sha512Output));
            CryptnoxUtils::secure_wipe(concat, sizeof(concat));
            return false;
        }

        /* Encrypt random data with Kenc (Bit padding) */
        uint8_t ciphertextOPC[48U] = { 0U };
        uint16_t cipherLength = _crypto.aesCbcEncrypt(RNG_data, sizeof(RNG_data),
                                                      ciphertextOPC,
                                                      session.aesKey, sizeof(session.aesKey),
                                                      iv_opc, true);

        /* Compute MAC over APDU header + ciphertext (Null padding) */
        uint8_t opcApduHeader[APDU_HEADER_LEN + APDU_LC_LEN] = {
            0x80U, 0x11U, 0x00U, 0x00U,
            (uint8_t)(cipherLength + AES_BLOCK_SIZE)
        };
        uint8_t MAC_apduHeader[AES_BLOCK_SIZE] = { 0U };
        memcpy(MAC_apduHeader, opcApduHeader, sizeof(opcApduHeader));

        size_t  MAC_data_length = sizeof(MAC_apduHeader) + cipherLength;
        uint8_t MAC_data[64U] = { 0U };
        uint8_t ciphertextMACLong[64U] = { 0U };

        if (MAC_data_length > sizeof(MAC_data)) {
            CryptnoxUtils::secure_wipe(sharedSecret, sizeof(sharedSecret));
            CryptnoxUtils::secure_wipe(sha512Output, sizeof(sha512Output));
            CryptnoxUtils::secure_wipe(concat, sizeof(concat));
            CryptnoxUtils::secure_wipe(RNG_data, sizeof(RNG_data));
            return false;
        }

        memcpy(MAC_data, MAC_apduHeader, sizeof(MAC_apduHeader));
        memcpy(MAC_data + sizeof(MAC_apduHeader), ciphertextOPC, cipherLength);

        uint16_t encryptedLengthMAC = _crypto.aesCbcEncrypt(MAC_data, (uint16_t)MAC_data_length,
                                                            ciphertextMACLong,
                                                            session.macKey, sizeof(session.macKey),
                                                            mac_iv, false);

        uint8_t MAC_value[AES_BLOCK_SIZE] = { 0U };
        uint8_t macOffset = (uint8_t)(encryptedLengthMAC - AES_BLOCK_SIZE);
        memcpy(MAC_value, ciphertextMACLong + macOffset, AES_BLOCK_SIZE);

        /* Forge MUTUALLY AUTHENTICATE APDU */
        uint8_t sendApduOpc[REQUEST_MUTUALLYAUTHENTICATE_IN_BYTES] = { 0U };
        uint16_t offset = 0U;
        memcpy(sendApduOpc + offset, opcApduHeader, sizeof(opcApduHeader));
        offset += sizeof(opcApduHeader);
        memcpy(sendApduOpc + offset, MAC_value, sizeof(MAC_value));
        offset += sizeof(MAC_value);
        memcpy(sendApduOpc + offset, ciphertextOPC, cipherLength);

        uint8_t response[RESPONSE_MUTUALLYAUTHENTICATE_IN_BYTES] = { 0U };
        uint8_t responseLength = sizeof(response);

        if (_driver.sendAPDU(sendApduOpc, sizeof(sendApduOpc), response, responseLength)) {
            /* Explicit upper-bound check before any buffer access — C2/M3 */
            if (responseLength > RESPONSE_MUTUALLYAUTHENTICATE_IN_BYTES) {
#if CW_DEBUG_LOGGING
                _logger.println(F("MutualAuth: response exceeds buffer size."));
#endif
            }
            else if (checkStatusWord(response, responseLength, 0x90U, 0x00U)) {
                if (responseLength == RESPONSE_MUTUALLYAUTHENTICATE_IN_BYTES) {
                    memcpy(session.iv, response, CW_IV_SIZE);
                    ret = true;
                } else {
#if CW_DEBUG_LOGGING
                    _logger.println(F("MutualAuth: unexpected response size."));
#endif
                }
            } else {
#if CW_DEBUG_LOGGING
                _logger.println(F("MutualAuth: bad SW."));
#endif
            }
        } else {
#if CW_DEBUG_LOGGING
            _logger.println(F("MutualAuth APDU failed."));
#endif
        }

        /* Secure cleanup */
        CryptnoxUtils::secure_wipe(sharedSecret, sizeof(sharedSecret));
        CryptnoxUtils::secure_wipe(sha512Output, sizeof(sha512Output));
        CryptnoxUtils::secure_wipe(concat, sizeof(concat));
        CryptnoxUtils::secure_wipe(RNG_data, sizeof(RNG_data));
        CryptnoxUtils::secure_wipe(ciphertextOPC, sizeof(ciphertextOPC));
        CryptnoxUtils::secure_wipe(MAC_data, sizeof(MAC_data));
    }

    return ret;
}

bool CW_SecureChannel::aesCbcEncrypt(CW_SecureSession& session,
                                     const uint8_t apdu[], uint16_t apduLength,
                                     const uint8_t data[], uint16_t dataLength,
                                     uint8_t* decryptedOutput, uint16_t* decryptedOutputLength) {
    bool ret = false;

    /* 1. Encrypt data with Kenc (Bit padding) */
    uint16_t encryptedLength = _crypto.aesCbcEncrypt(data, dataLength, s_dataBuf,
                                                     session.aesKey, sizeof(session.aesKey),
                                                     session.iv, true);

    uint16_t lcValue = encryptedLength + (uint16_t)AES_BLOCK_SIZE;
    uint8_t macApdu[MAC_APDU_LEN] = { 0U };
    macApdu[0U] = (uint8_t)lcValue;

    uint16_t macDataLength = apduLength + sizeof(macApdu) + encryptedLength;
    if (macDataLength > MAX_MAC_DATA_LEN) {
#if CW_DEBUG_LOGGING
        _logger.println(F("Error: MAC data length exceeds buffer."));
#endif
        return false;
    }

    /* 2. Build MAC input: APDU header || LC block || ciphertext */
    uint16_t offset = 0U;
    memcpy(s_macBuf, apdu, apduLength);
    offset += apduLength;
    memcpy(s_macBuf + offset, macApdu, sizeof(macApdu));
    offset += sizeof(macApdu);
    memcpy(s_macBuf + offset, s_dataBuf, encryptedLength);

    uint8_t macIv[AES_BLOCK_SIZE] = { 0U };
    uint16_t macEncryptedLength = _crypto.aesCbcEncrypt(s_macBuf, macDataLength, s_apduBuf,
                                                        session.macKey, sizeof(session.macKey),
                                                        macIv, false);

    uint8_t macValue[AES_BLOCK_SIZE] = { 0U };
    uint16_t macOffset = macEncryptedLength - AES_BLOCK_SIZE;
    memcpy(macValue, s_apduBuf + macOffset, AES_BLOCK_SIZE);

    /* 3. Build send APDU: header || Lc || MAC || ciphertext */
    const uint8_t lc = (uint8_t)lcValue;
    uint16_t sendApduLength = apduLength + APDU_LC_LEN + sizeof(macValue) + encryptedLength;
    if (sendApduLength > SEND_APDU_MAX_LEN) {
#if CW_DEBUG_LOGGING
        _logger.println(F("Error: Send APDU length exceeds buffer."));
#endif
        return false;
    }

    offset = 0U;
    memcpy(s_apduBuf, apdu, apduLength);
    offset += apduLength;
    s_apduBuf[offset] = lc;
    offset += APDU_LC_LEN;
    memcpy(s_apduBuf + offset, macValue, sizeof(macValue));
    offset += sizeof(macValue);
    memcpy(s_apduBuf + offset, s_dataBuf, encryptedLength);

    /* 4. Send APDU */
    uint8_t response[CW_MAX_APDU_RESPONSE_BYTES] = { 0U };
    uint8_t responseLength = sizeof(response);

    if (_driver.sendAPDU(s_apduBuf, sendApduLength, response, responseLength)) {
        if (checkStatusWord(response, responseLength, 0x90U, 0x00U)) {
            memcpy(session.iv, response, CW_IV_SIZE);
            ret = aesCbcDecrypt(session, response, responseLength, macValue,
                                decryptedOutput, decryptedOutputLength);
        } else {
#if CW_DEBUG_LOGGING
            _logger.println(F("Secured APDU: bad SW."));
#endif
        }
    } else {
#if CW_DEBUG_LOGGING
        _logger.println(F("Secured APDU failed."));
#endif
    }

    return ret;
}

bool CW_SecureChannel::aesCbcDecrypt(CW_SecureSession& session,
                                     uint8_t* response, size_t response_len,
                                     uint8_t* mac_value,
                                     uint8_t* decryptedOutput, uint16_t* decryptedOutputLength) {
    /* Response layout: MAC(16) || cipherText(N) || SW1(1) || SW2(1) */
    uint8_t rep_mac[AES_BLOCK_SIZE];
    memcpy(rep_mac, response, AES_BLOCK_SIZE);
    uint8_t* rep_data  = response + AES_BLOCK_SIZE;
    size_t totalDataLen = response_len - 2U;
    size_t cipherLen    = totalDataLen - AES_BLOCK_SIZE;

    if ((mac_value == NULL) || (cipherLen == 0U)) {
        return false;
    }

    /* Verify MAC: AES-CBC-MAC over [length_header(16)] || [all_ciphertext] */
    size_t macInputLen = AES_BLOCK_SIZE + cipherLen;
    if (macInputLen > sizeof(s_macBuf)) {
#if CW_DEBUG_LOGGING
        _logger.println(F("Error: Response too large for MAC verification."));
#endif
        return false;
    }

    memset(s_macBuf, 0U, AES_BLOCK_SIZE);
    s_macBuf[0] = (uint8_t)totalDataLen;
    memcpy(s_macBuf + AES_BLOCK_SIZE, rep_data, cipherLen);

    uint8_t mac_iv[AES_BLOCK_SIZE] = { 0U };
    uint16_t macEncryptedLength = _crypto.aesCbcEncrypt(s_macBuf, (uint16_t)macInputLen, s_apduBuf,
                                                        session.macKey, sizeof(session.macKey),
                                                        mac_iv, false);

    uint8_t recomputedMacValue[AES_BLOCK_SIZE] = { 0U };
    uint16_t macOffset = macEncryptedLength - AES_BLOCK_SIZE;
    memcpy(recomputedMacValue, s_apduBuf + macOffset, AES_BLOCK_SIZE);

    /* cppcheck-suppress misra-config
     * MISRA-C:2012 Rule 15.5: function has more than one point of exit.
     * Early return on MAC mismatch is intentional to prevent any further
     * processing of unauthenticated ciphertext. */
    if (!CryptnoxUtils::secure_compare(rep_mac, recomputedMacValue, AES_BLOCK_SIZE)) {
#if CW_DEBUG_LOGGING
        _logger.println(F("MAC mismatch."));
#endif
        return false;
    }

    /* Decrypt ciphertext using mac_value as IV (Bit padding removal) */
    uint16_t decryptedDataLength = _crypto.aesCbcDecrypt(rep_data, (uint16_t)cipherLen, s_dataBuf,
                                                         session.aesKey, sizeof(session.aesKey),
                                                         mac_value, true);

    bool ret = false;

    if (decryptedDataLength < 2U) {
#if CW_DEBUG_LOGGING
        _logger.println(F("Error: Decoded data too short."));
#endif
    }
    else if (decryptedDataLength > sizeof(s_dataBuf)) {
#if CW_DEBUG_LOGGING
        _logger.println(F("Error: Decoded data length exceeds buffer."));
#endif
    }
    else {
        uint8_t innerSW1 = s_dataBuf[decryptedDataLength - 2U];
        uint8_t innerSW2 = s_dataBuf[decryptedDataLength - 1U];
        uint16_t payloadLength = decryptedDataLength - 2U;

        if ((innerSW1 != 0x90U) || (innerSW2 != 0x00U)) {
#if CW_DEBUG_LOGGING
            _logger.print(F("Card error SW: 0x"));
            if (innerSW1 < 0x10U) { _logger.print(F("0")); }
            _logger.print(innerSW1, HEX);
            _logger.print(F(" 0x"));
            if (innerSW2 < 0x10U) { _logger.print(F("0")); }
            _logger.println(innerSW2, HEX);
#endif
        }
        else {
            ret = true;
        }

        if ((decryptedOutput != NULL) && (decryptedOutputLength != NULL)) {
            memcpy(decryptedOutput, s_dataBuf, payloadLength);
            *decryptedOutputLength = payloadLength;
        }
    }

    return ret;
}

/******************************************************************
 * Certificate verification — static helpers (CW_VERIFY_CERT only)
 ******************************************************************/

#if CW_VERIFY_CERT

bool CW_SecureChannel::findBytes(const uint8_t* hay, uint16_t hayLen,
                                 const uint8_t* needle, uint8_t needleLen,
                                 uint16_t& pos) {
    bool found = false;

    if ((hay != NULL) && (needle != NULL) && (hayLen >= (uint16_t)needleLen)) {
        uint16_t limit = hayLen - (uint16_t)needleLen;
        for (uint16_t i = 0U; i <= limit; i++) {
            bool match = true;
            for (uint8_t j = 0U; j < needleLen; j++) {
                if (hay[i + j] != needle[j]) {
                    match = false;
                    break;
                }
            }
            if (match) {
                pos = i;
                found = true;
                break;
            }
        }
    }

    return found;
}

bool CW_SecureChannel::parseDerSigToRaw(const uint8_t* der, uint8_t derLen,
                                        uint8_t* raw64) {
    bool ret = false;

    if ((der != NULL) && (raw64 != NULL) && (derLen >= 6U) && (der[0] == 0x30U)) {
        uint8_t pos = 2U;  /* skip SEQUENCE tag + length */

        if (der[pos] == 0x02U) {
            pos++;
            uint8_t rLen = der[pos];
            pos++;
            if ((pos + rLen) <= derLen) {
                const uint8_t* rPtr = der + pos;
                pos += rLen;

                if ((pos < derLen) && (der[pos] == 0x02U)) {
                    pos++;
                    uint8_t sLen = der[pos];
                    pos++;
                    if ((pos + sLen) <= derLen) {
                        const uint8_t* sPtr = der + pos;

                        memset(raw64, 0U, 64U);

                        /* r: strip optional leading 0x00 padding byte */
                        if ((rLen == 33U) && (rPtr[0] == 0x00U)) { rPtr++; rLen = 32U; }
                        if (rLen <= 32U) {
                            memcpy(raw64 + (32U - rLen), rPtr, rLen);
                        }

                        /* s: strip optional leading 0x00 padding byte */
                        if ((sLen == 33U) && (sPtr[0] == 0x00U)) { sPtr++; sLen = 32U; }
                        if (sLen <= 32U) {
                            memcpy(raw64 + 32U + (32U - sLen), sPtr, sLen);
                        }

                        ret = true;
                    }
                }
            }
        }
    }

    return ret;
}

bool CW_SecureChannel::verifyEcdsaSha256(const uint8_t* pubKey64,
                                         const uint8_t* message, uint16_t msgLen,
                                         const uint8_t* derSig, uint8_t derSigLen) {
    uint8_t hash[32U] = { 0U };
    uint8_t rawSig[64U] = { 0U };

    _crypto.sha256(message, msgLen, hash);

    if (!parseDerSigToRaw(derSig, derSigLen, rawSig)) {
        return false;
    }

    return (uECC_verify(pubKey64, hash, sizeof(hash), rawSig,
                        uECC_secp256r1()) != 0);
}

/******************************************************************
 * getManufacturerCertificate
 ******************************************************************/

bool CW_SecureChannel::getManufacturerCertificate(uint8_t* cert, uint16_t& certLen) {
    bool ret = false;
    certLen = 0U;

    if (cert != NULL) {
        /* Page 0: first 2 bytes of response data are big-endian total cert length. */
        uint8_t apdu[5U] = { 0x80U, 0xF7U, 0x00U, 0x00U, 0x00U };
        uint8_t response[130U];  /* 128 data + 2 SW */
        uint8_t responseLen = sizeof(response);

        if (_driver.sendAPDU(apdu, sizeof(apdu), response, responseLen) &&
            checkStatusWord(response, responseLen, 0x90U, 0x00U)) {

            uint8_t dataBytes = responseLen - 2U;  /* strip SW */

            if (dataBytes >= 2U) {
                uint16_t totalCertLen = ((uint16_t)response[0] << 8U) | response[1];

                if (totalCertLen <= CW_MANUF_CERT_MAX_BYTES) {
                    /* Copy cert bytes from this page (after the 2-byte length header). */
                    uint8_t certInPage = dataBytes - 2U;
                    if (certInPage > totalCertLen) { certInPage = (uint8_t)totalCertLen; }
                    memcpy(cert, response + 2U, certInPage);
                    certLen = certInPage;

                    /* Fetch additional pages until the full cert is assembled. */
                    uint8_t pageIdx = 1U;
                    while ((certLen < totalCertLen) && (pageIdx < 8U)) {
                        apdu[3] = pageIdx;
                        responseLen = sizeof(response);

                        if (!_driver.sendAPDU(apdu, sizeof(apdu), response, responseLen) ||
                            !checkStatusWord(response, responseLen, 0x90U, 0x00U)) {
                            break;
                        }

                        uint8_t pageData = responseLen - 2U;
                        uint16_t remaining = totalCertLen - certLen;
                        if (pageData > remaining) { pageData = (uint8_t)remaining; }

                        if ((certLen + pageData) > CW_MANUF_CERT_MAX_BYTES) { break; }
                        memcpy(cert + certLen, response, pageData);
                        certLen += pageData;
                        pageIdx++;
                    }

                    ret = (certLen == totalCertLen);
                    if (!ret) {
#if CW_DEBUG_LOGGING
                        _logger.println(F("getManufacturerCertificate: incomplete."));
#endif
                    }
                } else {
#if CW_DEBUG_LOGGING
                    _logger.println(F("getManufacturerCertificate: cert too large."));
#endif
                }
            }
        } else {
#if CW_DEBUG_LOGGING
            _logger.println(F("getManufacturerCertificate APDU failed."));
#endif
        }
    }

    return ret;
}

/******************************************************************
 * verifyCertificateChain
 ******************************************************************/

uint8_t CW_SecureChannel::verifyCertificateChain(const uint8_t* cardCert,
                                                  uint8_t cardCertLen) {
    uint8_t result = CW_CERT_OK;

    /* Basic input validation: tag 0x43, minimum length. */
    if ((cardCert == NULL) || (cardCertLen < 80U) || (cardCert[0] != 0x43U)) {
#if CW_DEBUG_LOGGING
        _logger.println(F("verifyCert: invalid card cert."));
#endif
        result = CW_CERT_FORMAT_ERROR;
    }

    /* --- Step 1: Retrieve the manufacturer certificate from the card. --- */
    uint16_t mfCertLen = 0U;
    if (result == CW_CERT_OK) {
        if (!getManufacturerCertificate(s_mfCertBuf, mfCertLen) || (mfCertLen < 20U)) {
#if CW_DEBUG_LOGGING
            _logger.println(F("verifyCert: failed to get mfr cert."));
#endif
            result = CW_CERT_FORMAT_ERROR;
        }
    }

    /* --- Step 2: Extract device public key from manufacturer cert. ---
     * Search for K1_PUBKEY_OID; the 65-byte uncompressed public key follows. */
    uint16_t k1OidPos = 0U;
    if (result == CW_CERT_OK) {
        if (!findBytes(s_mfCertBuf, mfCertLen, K1_PUBKEY_OID, sizeof(K1_PUBKEY_OID), k1OidPos)) {
#if CW_DEBUG_LOGGING
            _logger.println(F("verifyCert: device pubkey OID not found."));
#endif
            result = CW_CERT_KEY_NOT_FOUND;
        }
    }

    uint16_t pubkeyStart = 0U;
    if (result == CW_CERT_OK) {
        pubkeyStart = k1OidPos + (uint16_t)sizeof(K1_PUBKEY_OID);
        if ((pubkeyStart + 65U) > mfCertLen) {
#if CW_DEBUG_LOGGING
            _logger.println(F("verifyCert: device pubkey out of bounds."));
#endif
            result = CW_CERT_FORMAT_ERROR;
        }
    }

    const uint8_t* devicePubKey64 = NULL;
    if (result == CW_CERT_OK) {
        /* pubkey64 = X||Y (skip the 0x04 uncompressed-point prefix byte) */
        const uint8_t* devicePubKey65 = s_mfCertBuf + pubkeyStart;
        if (devicePubKey65[0] != 0x04U) {
#if CW_DEBUG_LOGGING
            _logger.println(F("verifyCert: unexpected pubkey prefix."));
#endif
            result = CW_CERT_FORMAT_ERROR;
        }
        else {
            devicePubKey64 = devicePubKey65 + 1U;  /* X||Y */
        }
    }

    /* --- Step 3: Verify manufacturer certificate against trusted CA key.
     *
     * Build the signed message following the Python SDK logic (authenticity.py):
     *   message = mfCert[4 .. k1OidPos + sizeof(K1_PUBKEY_OID) + 65]
     *   (i.e. skip 4-byte outer DER SEQUENCE header; stop at end of pubkey)
     *
     * Find the ECDSA-SHA256 BIT STRING that holds the CA's signature.
     * Layout after ECDSA_SHA256_OID: [bit_string_len][0x00][DER sig…] */
    const uint8_t MF_CERT_HEADER_SKIP = 4U;
    const uint8_t* mfMsg    = NULL;
    uint16_t       mfMsgLen = 0U;

    if (result == CW_CERT_OK) {
        if (k1OidPos <= MF_CERT_HEADER_SKIP) {
#if CW_DEBUG_LOGGING
            _logger.println(F("verifyCert: mfr cert structure error."));
#endif
            result = CW_CERT_FORMAT_ERROR;
        }
        else {
            mfMsg    = s_mfCertBuf + MF_CERT_HEADER_SKIP;
            mfMsgLen = (k1OidPos - MF_CERT_HEADER_SKIP) +
                       (uint16_t)sizeof(K1_PUBKEY_OID) + 65U;

            if ((MF_CERT_HEADER_SKIP + mfMsgLen) > mfCertLen) {
#if CW_DEBUG_LOGGING
                _logger.println(F("verifyCert: mfr cert msg out of bounds."));
#endif
                result = CW_CERT_FORMAT_ERROR;
            }
        }
    }

    if (result == CW_CERT_OK) {
        /* Find signature in manufacturer cert */
        uint16_t ecdsaOidPos = 0U;
        if (!findBytes(s_mfCertBuf, mfCertLen,
                       ECDSA_SHA256_OID, sizeof(ECDSA_SHA256_OID), ecdsaOidPos)) {
#if CW_DEBUG_LOGGING
            _logger.println(F("verifyCert: ECDSA-SHA256 OID not found in mfr cert."));
#endif
            result = CW_CERT_FORMAT_ERROR;
        }
        else {
            /* After the OID: [BIT_STRING_LEN][0x00][DER_SIG...] */
            uint16_t sigOffset = ecdsaOidPos + (uint16_t)sizeof(ECDSA_SHA256_OID);
            if ((sigOffset + 2U) > mfCertLen) {
                result = CW_CERT_FORMAT_ERROR;
            }
            else {
                uint8_t bitStringLen = s_mfCertBuf[sigOffset];
                sigOffset++;                    /* skip the BIT STRING length byte */
                if (s_mfCertBuf[sigOffset] == 0x00U) {
                    sigOffset++;                /* skip the 0x00 "unused bits" byte */
                    bitStringLen = (bitStringLen > 1U) ? (bitStringLen - 1U) : 0U;
                }
                if ((sigOffset + bitStringLen) > mfCertLen) {
                    result = CW_CERT_FORMAT_ERROR;
                }
                else {
                    const uint8_t* mfSig    = s_mfCertBuf + sigOffset;
                    uint8_t        mfSigLen = bitStringLen;

                    /* Try each embedded trusted CA key */
                    bool mfVerified = false;
                    for (uint8_t i = 0U; i < CW_TRUSTED_CA_COUNT; i++) {
                        if (verifyEcdsaSha256(CW_TRUSTED_CA_KEYS[i],
                                              mfMsg, mfMsgLen,
                                              mfSig, mfSigLen)) {
                            mfVerified = true;
                            break;
                        }
                    }
                    if (!mfVerified) {
#if CW_DEBUG_LOGGING
                        _logger.println(F("verifyCert: mfr cert sig INVALID — card NOT genuine."));
#endif
                        result = CW_CERT_MANUF_SIG_INVALID;
                    }
#if CW_DEBUG_LOGGING
                    else {
                        _logger.println(F("Manufacturer cert signature OK."));
                    }
#endif
                }
            }
        }
    }

    /* --- Step 4: Verify card certificate signature against device public key.
     * Message = cardCert[0..73] (74 bytes: tag + nonce + uncompressed pubkey).
     * Signature = cardCert[74..end] (DER ECDSA-SHA256). */
    const uint8_t CARD_CERT_MSG_LEN = 74U;  /* 1 + 8 + 65 */
    if (result == CW_CERT_OK) {
        if (cardCertLen <= CARD_CERT_MSG_LEN) {
#if CW_DEBUG_LOGGING
            _logger.println(F("verifyCert: card cert too short for sig."));
#endif
            result = CW_CERT_FORMAT_ERROR;
        }
        else {
            const uint8_t* cardSig    = cardCert + CARD_CERT_MSG_LEN;
            uint8_t        cardSigLen = cardCertLen - CARD_CERT_MSG_LEN;

            if (!verifyEcdsaSha256(devicePubKey64,
                                   cardCert, CARD_CERT_MSG_LEN,
                                   cardSig, cardSigLen)) {
#if CW_DEBUG_LOGGING
                _logger.println(F("verifyCert: card cert sig INVALID."));
#endif
                result = CW_CERT_CARD_SIG_INVALID;
            }
#if CW_DEBUG_LOGGING
            else {
                _logger.println(F("Card cert signature OK."));
            }
#endif
        }
    }

    /* --- Step 5: Anti-replay nonce check.
     * Only meaningful now that signatures are verified above. */
    if (result == CW_CERT_OK) {
        if ((cardCertLen <= (1U + CW_CERT_NONCE_SIZE)) ||
            (memcmp(cardCert + 1U, _lastNonce, CW_CERT_NONCE_SIZE) != 0)) {
#if CW_DEBUG_LOGGING
            _logger.println(F("verifyCert: nonce mismatch — possible replay."));
#endif
            result = CW_CERT_NONCE_MISMATCH;
        }
    }

#if CW_DEBUG_LOGGING
    if (result == CW_CERT_OK) {
        _logger.println(F("Certificate chain OK. Card is genuine."));
    }
#endif

    return result;
}

#endif /* CW_VERIFY_CERT */
