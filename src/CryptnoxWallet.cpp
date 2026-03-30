#include <Arduino.h>
#include "CryptnoxWallet.h"

/******************************************************************
 * Constructor
 ******************************************************************/

CryptnoxWallet::CryptnoxWallet(CW_NfcTransport& driver, CW_Logger& logger)
    : _driver(driver), _logger(logger), _crypto(), _secure(driver, logger, _crypto) {
}

/******************************************************************
 * Public methods
 ******************************************************************/

bool CryptnoxWallet::begin() {
    bool ret = _driver.begin();
    if (ret) {
        printPN532FirmwareVersion();
    }
    return ret;
}

// cppcheck-suppress unusedFunction
bool CryptnoxWallet::connect(CW_SecureSession& session) {
    bool ret = false;

    for (uint8_t attempt = 0U; (attempt < CW_CONNECT_MAX_ATTEMPTS) && (ret == false); attempt++) {
        if (attempt > 0U) {
            _logger.print(F("Retrying card connection (attempt "));
            _logger.print((uint8_t)(attempt + 1U));
            _logger.println(F(")..."));
            _driver.resetReader();
            delay(200);
        }

        if (_driver.inListPassiveTarget()) {
            delay(200);
            if (establishSecureChannel(session)) {
                ret = true;
            }
        }
    }

    return ret;
}

bool CryptnoxWallet::establishSecureChannel(CW_SecureSession& session) {
    bool ret = false;

    if (_secure.selectApdu()) {
        uint8_t cardCertificate[146U]; /* GETCARDCERTIFICATE_IN_BYTES */
        uint8_t cardCertificateLength = 0U;

        if (_secure.getCardCertificate(cardCertificate, cardCertificateLength)) {
            uint8_t cardEphemeralPubKey[64U]; /* CARDEPHEMERALPUBKEY_SIZE */
            if (_secure.extractCardEphemeralKey(cardCertificate, cardEphemeralPubKey)) {
                uint8_t openSecureChannelSalt[32U];
                uint8_t clientPrivateKey[32U];
                uint8_t clientPublicKey[64U];
                const uECC_Curve_t* sessionCurve = uECC_secp256r1();
                if (_secure.openSecureChannel(openSecureChannelSalt, clientPublicKey,
                                              clientPrivateKey, sessionCurve)) {
                    if (_secure.mutuallyAuthenticate(session, openSecureChannelSalt,
                                                    clientPublicKey, clientPrivateKey,
                                                    sessionCurve, cardEphemeralPubKey)) {
                        _logger.println(F("Secure channel established"));
                        ret = true;
                    } else {
                        _logger.println(F("Mutual authentication failed"));
                    }
                } else {
                    _logger.println(F("Failed to open secure channel"));
                }
            } else {
                _logger.println(F("Failed to extract card ephemeral key"));
            }
        } else {
            _logger.println(F("Failed to get card certificate"));
        }
    } else {
        _logger.println(F("Failed to select Cryptnox application"));
    }

    return ret;
}

// cppcheck-suppress unusedFunction
void CryptnoxWallet::disconnect(CW_SecureSession& session) {
    if (isSecureChannelOpen(session)) {
        session.clear();
    }
    _driver.resetReader();
}

// cppcheck-suppress unusedFunction
void CryptnoxWallet::getCardInfo(CW_SecureSession& session) {
    if (!isSecureChannelOpen(session)) {
        _logger.println(F("Error: Secure channel not open. Cannot get card info."));
        return;
    }
    uint8_t data[] = { 0x00U };
    uint8_t apdu[] = { 0x80U, 0xFAU, 0x00U, 0x00U };
    _secure.aesCbcEncrypt(session, apdu, sizeof(apdu), data, sizeof(data));
}

// cppcheck-suppress unusedFunction
void CryptnoxWallet::verifyPin(CW_SecureSession& session, const uint8_t* pin, uint8_t pinLength) {
    if (!isSecureChannelOpen(session)) {
        _logger.println(F("Error: Secure channel not open. Cannot verify PIN."));
    }
    else if ((pin == NULL) || (pinLength < CW_MIN_PIN_LENGTH) || (pinLength > CW_MAX_PIN_LENGTH)) {
        _logger.println(F("Error: Invalid PIN (must be 4-9 digits)."));
    }
    else {
        uint8_t paddedPin[CW_MAX_PIN_LENGTH] = { 0U };
        memcpy(paddedPin, pin, pinLength);
        uint8_t apdu[] = { 0x80U, 0x20U, 0x00U, 0x00U };
        _secure.aesCbcEncrypt(session, apdu, sizeof(apdu), paddedPin, CW_MAX_PIN_LENGTH);
    }
}

// cppcheck-suppress unusedFunction
bool CryptnoxWallet::writeUserData(CW_SecureSession& session, uint8_t slot,
                                    const uint8_t* data, uint16_t dataLength) {
    bool ret = false;

    if (!isSecureChannelOpen(session)) {
        _logger.println(F("Error: Secure channel not open. Cannot write user data."));
    }
    else if ((data == NULL) || (dataLength == 0U)) {
        _logger.println(F("Error: Invalid data for write user data."));
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

            uint8_t apdu[] = { 0x80U, 0xFCU, slot, page };

            _logger.print(F("Writing user data page "));
            _logger.print(page);
            _logger.print(F(" ("));
            _logger.print(chunkSize);
            _logger.println(F(" bytes)..."));

            if (!_secure.aesCbcEncrypt(session, apdu, sizeof(apdu), data + offset, chunkSize)) {
                _logger.print(F("Error: Write user data failed on page "));
                _logger.println(page);
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

// cppcheck-suppress unusedFunction
CW_SignResult CryptnoxWallet::sign(CW_SignRequest& request) {
    CW_SignResult result;

    if (validateSignRequest(request, result)) {
        uint8_t data[CW_HASH_SIZE + CW_MAX_DERIVE_PATH_LENGTH + CW_MAX_PIN_LENGTH] = { 0U };
        uint16_t dataLength = 0U;

        buildSignPayload(request, data, dataLength);

        uint8_t derResponse[255U] = { 0U };
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

/******************************************************************
 * Static public methods
 ******************************************************************/

bool CryptnoxWallet::parseDerSignature(const uint8_t* der, uint8_t derLength,
                                        uint8_t* r, uint8_t& rLength,
                                        uint8_t* s, uint8_t& sLength) {
    bool ret = false;

    if ((der == NULL) || (derLength < 6U) || (r == NULL) || (s == NULL)) {
        /* Invalid parameters */
    }
    else if (der[0] != CW_DER_TAG_SEQUENCE) {
        /* Missing DER SEQUENCE tag */
    }
    else {
        uint8_t pos = 2U;

        if (der[pos] != CW_DER_TAG_INTEGER) {
            /* Missing INTEGER tag for r */
        }
        else {
            pos++;
            rLength = der[pos];
            pos++;
            if ((pos + rLength) > derLength) {
                /* r exceeds bounds */
            }
            else {
                memcpy(r, der + pos, rLength);
                pos += rLength;

                if ((pos >= derLength) || (der[pos] != CW_DER_TAG_INTEGER)) {
                    /* Missing INTEGER tag for s */
                }
                else {
                    pos++;
                    sLength = der[pos];
                    pos++;
                    if ((pos + sLength) > derLength) {
                        /* s exceeds bounds */
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

/******************************************************************
 * Private methods
 ******************************************************************/

bool CryptnoxWallet::isSecureChannelOpen(const CW_SecureSession& session) const {
    uint8_t acc = 0U;
    for (uint8_t i = 0U; i < CW_AESKEY_SIZE; i++) {
        acc |= session.aesKey[i];
    }
    return (acc != 0U);
}

bool CryptnoxWallet::printPN532FirmwareVersion() {
    return _driver.printFirmwareVersion();
}

bool CryptnoxWallet::validateSignRequest(const CW_SignRequest& request, CW_SignResult& result) {
    bool ret = false;

    if (!isSecureChannelOpen(request.session)) {
        _logger.println(F("Error: Secure channel not open. Cannot sign."));
        result.errorCode = CW_INVALID_SESSION;
    }
    else if ((request.hash == NULL) || (request.hashLength == 0U)) {
        _logger.println(F("Error: Invalid parameters for sign."));
        result.errorCode = CW_SIGN_KEY_TOO_SHORT;
    }
    else if (request.hashLength > CW_HASH_SIZE) {
        _logger.println(F("Error: Hash too large."));
        result.errorCode = CW_SIGN_KEY_TOO_SHORT;
    }
    else if ((request.pinLessMode) && (request.keyType != CW_SIGN_PINLESS_K1)) {
        _logger.println(F("Error: PIN-less mode requires CW_SIGN_PINLESS_K1 key type."));
        result.errorCode = CW_SIGN_KEY_TOO_SHORT_WITH_PINLESS_MODE;
    }
    else {
        ret = true;

        if (!request.pinLessMode) {
            uint8_t pinLength = 0U;
            for (uint8_t i = 0U; i < CW_MAX_PIN_LENGTH; i++) {
                if (request.pin[i] == 0U) { break; }
                pinLength++;
            }
            if ((pinLength > 0U) && (pinLength < CW_MIN_PIN_LENGTH)) {
                _logger.println(F("Error: PIN too short (must be 4-9 digits)."));
                result.errorCode = CW_SIGN_PIN_INCORRECT;
                ret = false;
            }
        }
    }

    return ret;
}

void CryptnoxWallet::buildSignPayload(const CW_SignRequest& request,
                                       uint8_t* data, uint16_t& dataLength) {
    dataLength = request.hashLength;
    memcpy(data, request.hash, request.hashLength);

    if ((request.keyType == CW_SIGN_DERIVE_K1 || request.keyType == CW_SIGN_DERIVE_R1) &&
        (request.derivePath != NULL) && (request.derivePathLength > 0U)) {
        memcpy(data + dataLength, request.derivePath, request.derivePathLength);
        dataLength += request.derivePathLength;
    }

    if (!request.pinLessMode) {
        uint8_t pinLength = 0U;
        for (uint8_t i = 0U; i < CW_MAX_PIN_LENGTH; i++) {
            if (request.pin[i] == 0U) { break; }
            pinLength++;
        }
        if (pinLength > 0U) {
            memcpy(data + dataLength, request.pin, CW_MAX_PIN_LENGTH);
            dataLength += CW_MAX_PIN_LENGTH;
        }
    }
}

bool CryptnoxWallet::sendSignApdu(CW_SignRequest& request, const uint8_t* data,
                                   uint16_t dataLength, uint8_t* derResponse,
                                   uint16_t& derLength, CW_SignResult& result) {
    bool ret = false;
    uint8_t apdu[] = { 0x80U, 0xC0U, request.keyType, request.signatureType };

    _logger.println(F("Sending SIGN APDU..."));

    if (_secure.aesCbcEncrypt(request.session, apdu, sizeof(apdu), data, dataLength,
                               derResponse, &derLength)) {
        ret = true;
    }
    else {
        _logger.println(F("Sign APDU failed."));
        result.errorCode = CW_SIGN_NO_KEY_LOADED;
    }

    return ret;
}

bool CryptnoxWallet::extractRawSignature(const uint8_t* derResponse, uint16_t derLength,
                                          CW_SignResult& result) {
    bool ret = false;

    if ((derLength < 2U) || (derResponse[0] != CW_DER_TAG_SEQUENCE)) {
        _logger.println(F("Error: Invalid signature data (missing DER SEQUENCE tag)."));
        result.errorCode = CW_NOK;
    }
    else {
        uint8_t derContentLength = derResponse[1];
        uint8_t derTotalLength   = 2U + derContentLength;

        if (derTotalLength > derLength) {
            _logger.println(F("Error: DER signature length exceeds response."));
            result.errorCode = CW_NOK;
        }
        else {
            uint8_t r[33U] = { 0U };
            uint8_t s[33U] = { 0U };
            uint8_t rLen = 0U;
            uint8_t sLen = 0U;

            if (!parseDerSignature(derResponse, derTotalLength, r, rLen, s, sLen)) {
                _logger.println(F("Error: Failed to parse DER signature."));
                result.errorCode = CW_NOK;
            }
            else {
                memset(result.signature, 0U, CW_RAW_SIGNATURE_SIZE);

                if (rLen > 0U) {
                    uint8_t rSrc = 0U;
                    uint8_t rDstLen = 32U;
                    if ((rLen == 33U) && (r[0] == 0x00U)) { rSrc = 1U; rLen = 32U; }
                    if (rLen <= rDstLen) {
                        memcpy(result.signature + (rDstLen - rLen), r + rSrc, rLen);
                    }
                }

                if (sLen > 0U) {
                    uint8_t sSrc = 0U;
                    uint8_t sDstLen = 32U;
                    if ((sLen == 33U) && (s[0] == 0x00U)) { sSrc = 1U; sLen = 32U; }
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

void CryptnoxWallet::debugPrintSignature(const uint8_t* signature) {
    _logger.print(F("Signature ("));
    _logger.print((uint8_t)CW_RAW_SIGNATURE_SIZE);
    _logger.println(F(" bytes):"));
    for (uint8_t i = 0U; i < CW_RAW_SIGNATURE_SIZE; i++) {
        _logger.print(F("0x"));
        if (signature[i] < 0x10U) _logger.print(F("0"));
        _logger.print(signature[i], HEX);
        _logger.print(F(" "));
        if ((i + 1U) % 16U == 0U && (i + 1U) != CW_RAW_SIGNATURE_SIZE) _logger.println();
    }
    _logger.println();
}
