#ifndef CW_SECURECHANNEL_H
#define CW_SECURECHANNEL_H

/******************************************************************
 * 1. Included files
 ******************************************************************/

#include <Arduino.h>
#include "CW_NfcTransport.h"
#include "CW_Logger.h"
#include "CW_CryptoProvider.h"
#include "CW_Defs.h"          /* for CW_SecureSession and constants */
#include "uECC.h"

/******************************************************************
 * 2. Class declaration
 ******************************************************************/

/**
 * @class CW_SecureChannel
 * @brief Implements the Cryptnox secure channel protocol over NFC.
 *
 * Handles all low-level APDU exchanges required to establish and use
 * a secure session with the Cryptnox smart card:
 *  - Application selection (SELECT APDU)
 *  - Card certificate retrieval and ephemeral key extraction
 *  - ECDH-based session key derivation (OPEN SECURE CHANNEL + MUTUALLY AUTHENTICATE)
 *  - AES-CBC-MAC secure messaging (encrypt / decrypt / MAC verify)
 *  - Status word checking
 *
 * CW_SecureChannel is composed inside CryptnoxWallet and is not
 * intended to be used directly by application code.
 */
class CW_SecureChannel {
public:
    /**
     * @brief Construct a CW_SecureChannel.
     *
     * @param driver Reference to the NFC transport.
     * @param logger Reference to the logging interface.
     * @param crypto Reference to the crypto provider.
     */
    CW_SecureChannel(CW_NfcTransport& driver, CW_Logger& logger, CW_CryptoProvider& crypto);

    CW_SecureChannel(const CW_SecureChannel&) = delete;
    CW_SecureChannel& operator=(const CW_SecureChannel&) = delete;

    /**
     * @brief Send the SELECT APDU to activate the Cryptnox application.
     * @return true on success, false otherwise.
     */
    bool selectApdu();

    /**
     * @brief Retrieve the card's ephemeral public key via GET CARD CERTIFICATE.
     *
     * @param[out] cardCertificate       Buffer to receive the raw certificate bytes.
     * @param[out] cardCertificateLength Actual certificate length (bytes).
     * @return true on success, false otherwise.
     */
    bool getCardCertificate(uint8_t* cardCertificate, uint8_t& cardCertificateLength);

    /**
     * @brief Extract the card's ephemeral EC P-256 public key from a certificate.
     *
     * @param[in]  cardCertificate      Raw certificate bytes.
     * @param[out] cardEphemeralPubKey  64-byte key (X||Y, no 0x04 prefix) for ECDH.
     * @param[out] fullEphemeralPubKey65 Optional 65-byte key including 0x04 prefix.
     * @return true on success, false otherwise.
     */
    bool extractCardEphemeralKey(const uint8_t* cardCertificate,
                                 uint8_t* cardEphemeralPubKey,
                                 uint8_t* fullEphemeralPubKey65 = NULL);

    /**
     * @brief Send OPEN SECURE CHANNEL and retrieve the session salt.
     *
     * Generates a client EC key pair and sends the public key to the card.
     *
     * @param[out] salt            32-byte session salt from the card.
     * @param[out] clientPublicKey 64-byte generated client public key.
     * @param[out] clientPrivateKey 32-byte generated client private key.
     * @param[in]  sessionCurve   ECC curve for key generation (secp256r1).
     * @return true on success, false otherwise.
     */
    bool openSecureChannel(uint8_t* salt,
                           uint8_t* clientPublicKey,
                           uint8_t* clientPrivateKey,
                           const uECC_Curve_t* sessionCurve);

    /**
     * @brief Perform ECDH key derivation and MUTUALLY AUTHENTICATE with the card.
     *
     * Derives Kenc and Kmac from the ECDH shared secret, encrypts a random
     * challenge, sends MUTUALLY AUTHENTICATE, and sets the initial rolling IV.
     *
     * @param[out] session          Secure session to populate with keys and IV.
     * @param[in]  salt             32-byte session salt.
     * @param[in]  clientPublicKey  64-byte client public key.
     * @param[in]  clientPrivateKey 32-byte client private key.
     * @param[in]  sessionCurve    ECC curve.
     * @param[in]  cardEphemeralPubKey 64-byte card ephemeral public key.
     * @return true on success, false otherwise.
     */
    bool mutuallyAuthenticate(CW_SecureSession& session,
                              const uint8_t* salt,
                              uint8_t* clientPublicKey,
                              uint8_t* clientPrivateKey,
                              const uECC_Curve_t* sessionCurve,
                              uint8_t* cardEphemeralPubKey);

    /**
     * @brief AES-CBC encrypt payload, compute MAC, send APDU, and decrypt response.
     *
     * Full SCP03-style secure messaging pipeline:
     *  1. Encrypt @p data with AES-CBC (Bit padding) using session.aesKey / session.iv
     *  2. Compute AES-CBC-MAC over header + ciphertext using session.macKey
     *  3. Build and send APDU: header || Lc || MAC || ciphertext
     *  4. On success, update rolling IV and call aesCbcDecrypt on the response
     *
     * @param[in,out] session               Secure session (keys + rolling IV).
     * @param[in]     apdu                  4-byte APDU header (CLA, INS, P1, P2).
     * @param[in]     apduLength            Header length (must be 4).
     * @param[in]     data                  Plaintext payload.
     * @param[in]     dataLength            Plaintext length.
     * @param[out]    decryptedOutput       Optional buffer for decrypted response.
     * @param[out]    decryptedOutputLength Optional pointer to receive decrypted length.
     * @return true if APDU sent and response verified/decrypted successfully.
     */
    bool aesCbcEncrypt(CW_SecureSession& session,
                       const uint8_t apdu[], uint16_t apduLength,
                       const uint8_t data[], uint16_t dataLength,
                       uint8_t* decryptedOutput = NULL,
                       uint16_t* decryptedOutputLength = NULL);

    /**
     * @brief Verify MAC and decrypt an encrypted APDU response.
     *
     * @param[in,out] session               Secure session.
     * @param[in]     response              Encrypted response buffer (MAC || cipher || SW).
     * @param[in]     responseLen           Response length.
     * @param[in]     macValue              MAC from the last sent message (used as decrypt IV).
     * @param[out]    decryptedOutput       Optional buffer for decrypted payload.
     * @param[out]    decryptedOutputLength Optional pointer to receive decrypted length.
     * @return true if MAC matches and decryption succeeds, false otherwise.
     */
    bool aesCbcDecrypt(CW_SecureSession& session,
                       uint8_t* response, size_t responseLen,
                       uint8_t* macValue,
                       uint8_t* decryptedOutput = NULL,
                       uint16_t* decryptedOutputLength = NULL);

    /**
     * @brief Verify the SW1/SW2 status word at the end of an APDU response.
     *
     * @param response       APDU response buffer.
     * @param responseLength Response length.
     * @param sw1Expected    Expected SW1 byte.
     * @param sw2Expected    Expected SW2 byte.
     * @return true if last two bytes match expectations, false otherwise.
     */
    bool checkStatusWord(const uint8_t* response, uint8_t responseLength,
                         uint8_t sw1Expected, uint8_t sw2Expected);

private:
    CW_NfcTransport&  _driver; ///< NFC transport for APDU exchange.
    CW_Logger&        _logger; ///< Logging interface.
    CW_CryptoProvider& _crypto; ///< Crypto operations (AES, SHA, ECDH, RNG).
};

#endif // CW_SECURECHANNEL_H
