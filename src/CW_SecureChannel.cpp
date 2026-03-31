#include "CW_SecureChannel.h"
#include "CryptnoxUtils.h"

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

/* Shared static crypto scratch buffers — reuse is safe because decrypt is
 * always called from inside encrypt AFTER encrypt's large buffers are done. */
static uint8_t s_apduBuf[SEND_APDU_MAX_LEN];  /* 245 bytes */
static uint8_t s_macBuf [MAX_MAC_DATA_LEN];   /* 240 bytes */
static uint8_t s_dataBuf[ENC_BUF_MAX_LEN];   /* 224 bytes */

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
        _logger.println(F("checkStatusWord: response too short."));
    }
    else {
        uint8_t sw1 = response[responseLength - 2U];
        uint8_t sw2 = response[responseLength - 1U];

        if ((sw1 == sw1Expected) && (sw2 == sw2Expected)) {
            ret = true;
        }
        else {
            _logger.print(F("SW: 0x"));
            if (sw1 < 16U) _logger.print(F("0"));
            _logger.print(sw1, HEX);
            _logger.print(F(" 0x"));
            if (sw2 < 16U) _logger.print(F("0"));
            _logger.println(sw2, HEX);
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
            _logger.println(F("Select APDU failed."));
        }
    } else {
        _logger.println(F("APDU select failed."));
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

        uint8_t getCardCertificateApdu[] = {
            0x80, 0xF8, 0x00, 0x00, 0x08
        };

        uint8_t fullApdu[sizeof(getCardCertificateApdu) + RANDOM_BYTES];
        memcpy(fullApdu, getCardCertificateApdu, sizeof(getCardCertificateApdu));
        memcpy(fullApdu + sizeof(getCardCertificateApdu), randomBytes, RANDOM_BYTES);

        if (_driver.sendAPDU(fullApdu, sizeof(fullApdu),
                             getCardCertificateResponse, getCardCertificateResponseLength)) {
            if (checkStatusWord(getCardCertificateResponse, getCardCertificateResponseLength,
                                0x90U, 0x00U)) {
                cardCertificateLength = getCardCertificateResponseLength - RESPONSE_STATUS_WORDS_IN_BYTES;
                memcpy(cardCertificate, getCardCertificateResponse, cardCertificateLength);
                ret = true;
            } else {
                _logger.println(F("getCardCertificate: bad SW."));
            }
        } else {
            _logger.println(F("getCardCertificate APDU failed."));
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
        _logger.println(F("ECC key generation failed."));
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
            if (checkStatusWord(response, responseLength, 0x90U, 0x00U)) {
                if (responseLength == RESPONSE_OPENSECURECHANNEL_IN_BYTES) {
                    memcpy(salt, response, OPENSECURECHANNEL_SALT_IN_BYTES);
                    ret = true;
                } else {
                    _logger.println(F("OpenSecureChannel: unexpected response size."));
                }
            } else {
                _logger.println(F("OpenSecureChannel: bad SW."));
            }
        } else {
            _logger.println(F("OpenSecureChannel APDU failed."));
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
        _logger.println(F("ECDH failed."));
    }
    else {
        uint8_t concat[32U + sizeof(COMMON_PAIRING_DATA) - 1U + 32U] = { 0U };
        uint8_t sha512Output[64U] = { 0U };
        const size_t pairingKeyLen = sizeof(COMMON_PAIRING_DATA) - 1U;
        const size_t concatLen    = 32U + pairingKeyLen + 32U;

        memcpy(concat, sharedSecret, 32U);
        memcpy(concat + 32U, COMMON_PAIRING_DATA, pairingKeyLen);
        memcpy(concat + 32U + pairingKeyLen, salt, 32U);

        _crypto.sha512(concat, concatLen, sha512Output);

        memcpy(session.aesKey, sha512Output, CW_AESKEY_SIZE);
        memcpy(session.macKey, sha512Output + CW_AESKEY_SIZE, CW_MACKEY_SIZE);

        uint8_t iv_opc[AES_BLOCK_SIZE] = { 0U };
        uint8_t mac_iv[AES_BLOCK_SIZE] = { 0U };
        memset(iv_opc, 0x01U, AES_BLOCK_SIZE);

        uint8_t RNG_data[32U] = { 0U };
        // cppcheck-suppress misra-config
        if (!_crypto.random(RNG_data, sizeof(RNG_data))) {
            _logger.println(F("RNG failed."));
            memset(sharedSecret, 0U, sizeof(sharedSecret));
            memset(sha512Output, 0U, sizeof(sha512Output));
            memset(concat, 0U, sizeof(concat));
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
            memset(sharedSecret, 0U, sizeof(sharedSecret));
            memset(sha512Output, 0U, sizeof(sha512Output));
            memset(concat, 0U, sizeof(concat));
            memset(RNG_data, 0U, sizeof(RNG_data));
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

        uint8_t response[255U] = { 0U };
        uint8_t responseLength = sizeof(response);

        if (_driver.sendAPDU(sendApduOpc, sizeof(sendApduOpc), response, responseLength)) {
            if (checkStatusWord(response, responseLength, 0x90U, 0x00U)) {
                if (responseLength == RESPONSE_MUTUALLYAUTHENTICATE_IN_BYTES) {
                    memcpy(session.iv, response, CW_IV_SIZE);
                    ret = true;
                } else {
                    _logger.println(F("MutualAuth: unexpected response size."));
                }
            } else {
                _logger.println(F("MutualAuth: bad SW."));
            }
        } else {
            _logger.println(F("MutualAuth APDU failed."));
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
        _logger.println(F("Error: MAC data length exceeds buffer."));
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
        _logger.println(F("Error: Send APDU length exceeds buffer."));
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
    uint8_t response[255U] = { 0U };
    uint8_t responseLength = sizeof(response);

    if (_driver.sendAPDU(s_apduBuf, sendApduLength, response, responseLength)) {
        if (checkStatusWord(response, responseLength, 0x90U, 0x00U)) {
            memcpy(session.iv, response, CW_IV_SIZE);
            ret = aesCbcDecrypt(session, response, responseLength, macValue,
                                decryptedOutput, decryptedOutputLength);
        } else {
            _logger.println(F("Secured APDU: bad SW."));
        }
    } else {
        _logger.println(F("Secured APDU failed."));
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
        _logger.println(F("Error: Response too large for MAC verification."));
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

    // cppcheck-suppress misra-config
    if (!CryptnoxUtils::secure_compare(rep_mac, recomputedMacValue, AES_BLOCK_SIZE)) {
        _logger.println(F("MAC mismatch."));
        return false;
    }

    /* Decrypt ciphertext using mac_value as IV (Bit padding removal) */
    uint16_t decryptedDataLength = _crypto.aesCbcDecrypt(rep_data, (uint16_t)cipherLen, s_dataBuf,
                                                         session.aesKey, sizeof(session.aesKey),
                                                         mac_value, true);

    bool ret = false;

    if (decryptedDataLength < 2U) {
        _logger.println(F("Error: Decoded data too short."));
    }
    else if (decryptedDataLength > sizeof(s_dataBuf)) {
        _logger.println(F("Error: Decoded data length exceeds buffer."));
    }
    else {
        uint8_t innerSW1 = s_dataBuf[decryptedDataLength - 2U];
        uint8_t innerSW2 = s_dataBuf[decryptedDataLength - 1U];
        uint16_t payloadLength = decryptedDataLength - 2U;

        if ((innerSW1 != 0x90U) || (innerSW2 != 0x00U)) {
            _logger.print(F("Card error SW: 0x"));
            if (innerSW1 < 0x10U) _logger.print(F("0"));
            _logger.print(innerSW1, HEX);
            _logger.print(F(" 0x"));
            if (innerSW2 < 0x10U) _logger.print(F("0"));
            _logger.println(innerSW2, HEX);
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
