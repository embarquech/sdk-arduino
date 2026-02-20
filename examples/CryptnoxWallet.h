#ifndef CRYPTNOXWALLET_H
#define CRYPTNOXWALLET_H

/******************************************************************
 * 1. Included files (microcontroller ones then user defined ones)
 ******************************************************************/

#include <Arduino.h>
#include "NFCDriver.h"
#include "SerialDriver.h"
#include "uECC.h"

/******************************************************************
 * 2. Constants / define declarations
 ******************************************************************/

#define CW_AESKEY_SIZE    (32U)  /**< AES-256 session encryption key size in bytes */
#define CW_MACKEY_SIZE    (32U)  /**< AES-256 session MAC key size in bytes */
#define CW_IV_SIZE        (16U)  /**< AES-CBC IV size in bytes */

/* Generic error codes */
#define CW_OK                         (0x00U)  /**< OK */
#define CW_NOK                        (0x01U)  /**< NOK */
#define CW_INVALID_SESSION            (0x02U)  /**< Invalid session */

/* Key / path types for SIGN command (keyType) */
#define CW_SIGN_CURR_K1               (0x00U)  /**< Current key (k1) */
#define CW_SIGN_CURR_R1               (0x10U)  /**< Current key (r1) */
#define CW_SIGN_DERIVE_K1             (0x01U)  /**< Derive with k1 curve + derive flag for source */
#define CW_SIGN_DERIVE_R1             (0x11U)  /**< Derive with r1 curve + derive flag for source */
#define CW_SIGN_PINLESS_K1            (0x03U)  /**< PIN-less path (k1 only) */

/* PIN mode for SIGN command (pinLessMode) */
#define CW_SIGN_WITH_PIN              (false)  /**< PIN path */
#define CW_SIGN_PINLESS               (true)   /**< PIN-less path */

/* Signature types for SIGN command (signatureType) */
#define CW_SIGN_SIG_ECDSA_LOW_S       (0x00U)  /**< ECDSA with canonical low S */
#define CW_SIGN_SIG_ECDSA_EOSIO       (0x01U)  /**< ECDSA with filter signature to fit EOSIO standard */
#define CW_SIGN_SIG_SCHNORR_BIP340    (0x02U)  /**< Bitcoin Schnorr BIP340 signature, only with k1 */

/* SIGN-specific error codes */
#define CW_SIGN_KEY_TOO_SHORT                  (0x80U)  /**< Key is too short < 32-byte long or less 36 bytes and/or path not modulo 4 (w derive) */
#define CW_SIGN_NO_KEY_LOADED                  (0x81U)  /**< No key loaded */
#define CW_SIGN_PIN_INCORRECT                  (0x82U)  /**< Incorrect PIN */
#define CW_SIGN_KEY_TOO_SHORT_WITH_PINLESS_MODE (0x83U) /**< Key is too short with PIN-less mode */

#define CW_RAW_SIGNATURE_SIZE         (64U)    /**< Raw signature size (r[32] + s[32]) */
#define CW_HASH_SIZE                  (32U)    /**< Standard hash size (SHA-256, Keccak-256) */
#define CW_MIN_PIN_LENGTH              (4U)    /**< Minimum PIN code length (digits) */
#define CW_MAX_PIN_LENGTH              (9U)    /**< Maximum PIN code length (digits) */

/* User data write configuration */
#define CW_USER_DATA_PAGE_SIZE         (1200U) /**< Max plaintext bytes per write user data page */

/* Connect retry configuration */
#define CW_CONNECT_MAX_ATTEMPTS        (5U)    /**< Maximum NFC connection retry attempts */

/* DER encoding tags (ASN.1) */
#define CW_DER_TAG_SEQUENCE           (0x30U)  /**< DER SEQUENCE tag */
#define CW_DER_TAG_INTEGER            (0x02U)  /**< DER INTEGER tag */

/******************************************************************
 * 3. Typedefs / enum / structs
 ******************************************************************/

/**
 * @struct CW_SecureSession
 * @brief Holds cryptographic session state for reentrant secure channel operations.
 *
 * This struct encapsulates all session-specific cryptographic material,
 * allowing functions to be reentrant by passing session state as a parameter
 * rather than storing it as class member variables.
 */
struct CW_SecureSession {
    uint8_t aesKey[CW_AESKEY_SIZE];  /**< AES-256 session encryption key (Kenc) */
    uint8_t macKey[CW_MACKEY_SIZE];  /**< AES-256 session MAC key (Kmac) */
    uint8_t iv[CW_IV_SIZE];          /**< Current AES-CBC IV (rolling IV for secure messaging) */

    /** @brief Initialize all session keys and IV to zero. */
    CW_SecureSession() {
        memset(aesKey, 0U, sizeof(aesKey));
        memset(macKey, 0U, sizeof(macKey));
        memset(iv, 0U, sizeof(iv));
    }

    /** @brief Securely clear all session keys and IV. */
    void clear() {
        memset(aesKey, 0U, sizeof(aesKey));
        memset(macKey, 0U, sizeof(macKey));
        memset(iv, 0U, sizeof(iv));
    }
};

/**
 * @struct CW_SignRequest
 * @brief Request parameters for the sign operation.
 *
 * Contains all inputs needed to generate a signature using the Cryptnox card.
 */
struct CW_SignRequest {
    CW_SecureSession& session;       /**< Reference to a valid secure session */
    uint8_t keyType;                 /**< Key / path type (e.g. CW_SIGN_CURR_K1, CW_SIGN_DERIVE_R1) */
    uint8_t signatureType;           /**< Signature type (e.g. CW_SIGN_SIG_ECDSA_LOW_S) */
    uint8_t pin[CW_MAX_PIN_LENGTH];  /**< PIN must contain 6 to 9 digits */
    bool pinLessMode;                /**< false = PIN path, true = PIN-less path */
    const uint8_t* hash;             /**< Pointer to the hash to sign (typically 32 bytes) */
    uint8_t hashLength;              /**< Length of the hash in bytes */

    /**
     * @brief Construct a CW_SignRequest with required parameters.
     * @param sess      Reference to the secure session.
     * @param kType     Key / path type.
     * @param sigType   Signature type.
     * @param pinless   PIN-less mode flag (default: CW_SIGN_WITH_PIN).
     */
    explicit CW_SignRequest(CW_SecureSession& sess,
                            uint8_t kType = CW_SIGN_CURR_K1,
                            uint8_t sigType = CW_SIGN_SIG_ECDSA_LOW_S,
                            bool pinless = CW_SIGN_WITH_PIN)
        : session(sess), keyType(kType), signatureType(sigType),
          pinLessMode(pinless), hash(NULL), hashLength(0U) {
        memset(pin, 0U, sizeof(pin));
    }
};

/**
 * @struct CW_SignResult
 * @brief Result of the sign operation.
 *
 * Contains the generated signature and an error code indicating success or failure.
 */
struct CW_SignResult {
    uint8_t signature[CW_RAW_SIGNATURE_SIZE]; /**< Raw signature (r[32] + s[32]) */
    uint8_t errorCode;                        /**< Error code (CW_OK on success) */

    /** @brief Initialize result with zeroed signature and CW_NOK error code. */
    CW_SignResult() : errorCode(CW_NOK) {
        memset(signature, 0U, sizeof(signature));
    }
};

/******************************************************************
 * 4. Free functions / file-scope functions
 ******************************************************************/

/**
 * @class CryptnoxWallet
 * @brief High-level interface for interacting with a PN532-based wallet.
 *
 * This class encapsulates NFC card operations specific to the Cryptnox wallet,
 * including sending APDUs, retrieving the card certificate, and reading the UID.
 * It supports all bus types provided by Adafruit_PN532 (I2C, SPI, Software SPI, UART)
 * via constructor overloading.
 */
class CryptnoxWallet {
public:
    /**
     * @brief Construct a CryptnoxWallet over I2C.
     *
     * @param irq Pin number for PN532 IRQ (use -1 if unused).
     * @param reset Pin number for PN532 RESET (use -1 if unused).
     * @param theWire TwoWire instance (default is &Wire).
     * @param driver Reference to an NFCDriver implementation for NFC communication.
     * @param serial Reference to a SerialDriver implementation for debug output.
     */
    CryptnoxWallet(NFCDriver& driver, SerialDriver& serial) : driver(driver), serial(serial) {}

    /**
     * @brief Initialize the PN532 module via the underlying driver.
     *
     * Performs SAM configuration and prints firmware version.
     *
     * @return true if the module was successfully initialized, false otherwise.
     */
    bool begin() {
        bool ret = driver.begin();
        if (ret) {
            printPN532FirmwareVersion();
        }
        return ret;
    }

    /**
    * @brief Connect to the Cryptnox card and establish a secure channel.
    *
    * Detects if an ISO-DEP capable card is present, then establishes a secure channel
    * by selecting the Cryptnox application, retrieving the card certificate, performing ECDH key
    * exchange, and mutually authenticating with the card.
    *
    * Retries the full card activation sequence (NFC detection + SELECT + secure channel)
    * up to 5 times. When the SELECT APDU fails, the NFC field is reset and the card is
    * re-detected before retrying, which is necessary because a failed SELECT leaves the
    * NFC link in a broken state.
    *
    * @param[out] session Reference to the secure session to be populated with keys and IV.
    * @return true if the card was detected and secure channel was established successfully, false otherwise.
    */
    bool connect(CW_SecureSession& session);

    /**
    * @brief Establish a secure channel with the Cryptnox card.
    *
    * This function handles all the steps required to establish a secure session:
    * - Selects the Cryptnox application
    * - Retrieves the card certificate
    * - Performs ECDH key exchange
    * - Mutually authenticates with the card
    *
    * @param[out] session Reference to the secure session to be populated with keys and IV.
    * @return true if secure channel was established successfully, false otherwise.
    */
    bool establishSecureChannel(CW_SecureSession& session);

    /**
    * @brief Disconnect from the Cryptnox card and clear the secure session.
    *
    * This function securely clears all session keys and resets the NFC reader
    * for the next card detection. 
    *
    * IMPORTANT: This function MUST be called at the end of each card processing
    * iteration, even if connect() failed. Without calling disconnect(), the
    * reader will not reset and subsequent card detections will fail.
    *
    * @param[in,out] session Reference to the secure session to clear.
    */
    void disconnect(CW_SecureSession& session);

    /**
    * @brief Sends a secured GET CARD INFO APDU.
    * @param[in,out] session Reference to the secure session containing keys and IV.
    */
    void getCardInfo(CW_SecureSession& session);

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
    void verifyPin(CW_SecureSession& session, const uint8_t* pin, uint8_t pinLength);

    /**
    * @brief Generates a signature using the specified key and signature type.
    *
    * Sends the hash to the card over the secure channel for signing.
    * The card performs the signing internally and returns a signature.
    *
    * APDU: CLA=0x80, INS=0xC0, P1=keyType, P2=signatureType
    * Data: hash [+ optional PIN]
    * Response: DER signature → parsed to raw (r[32] + s[32])
    *
    * @param[in]  request  CW_SignRequest containing session, keyType, signatureType, pin, hash.
    * @return CW_SignResult containing signature[64] and errorCode.
    */
    CW_SignResult sign(CW_SignRequest& request);

    /**
    * @brief Writes data to a user memory slot, paginating in CW_USER_DATA_PAGE_SIZE pages.
    *
    * Splits the data into pages of at most CW_USER_DATA_PAGE_SIZE (1200) bytes.
    * Each page is sent as a separate secured APDU using AES-CBC encryption.
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
    bool writeUserData(CW_SecureSession& session, uint8_t slot,
                       const uint8_t* data, uint16_t dataLength);

    /**
    * @brief Parse a DER-encoded ECDSA signature to extract raw r and s values.
    *
    * DER format: 0x30 [total-length] 0x02 [r-length] [r] 0x02 [s-length] [s]
    *
    * Useful for blockchain transaction formatting (Ethereum, XRP, etc.) where
    * raw (r, s) values are needed instead of DER encoding.
    *
    * @param[in]  der       Pointer to DER-encoded signature bytes.
    * @param[in]  derLength Length of the DER signature.
    * @param[out] r         Buffer to receive the r value (must be at least 33 bytes).
    * @param[out] rLength   Actual length of r written.
    * @param[out] s         Buffer to receive the s value (must be at least 33 bytes).
    * @param[out] sLength   Actual length of s written.
    * @return true if parsing succeeded, false otherwise.
    */
    static bool parseDerSignature(const uint8_t* der, uint8_t derLength,
                                  uint8_t* r, uint8_t& rLength,
                                  uint8_t* s, uint8_t& sLength);

private:
    NFCDriver& driver; /**< PN532 driver for low-level NFC operations */
    SerialDriver& serial; /**< Serial driver for debug output */

        /**
     * @brief Send the SELECT APDU to select the wallet application.
     *
     * @return true if the APDU exchange succeeded, false otherwise.
     */
     bool selectApdu();

     /**
     * @brief Retrieves the card's ephemeral public key with a GET CARD CERTIFICATE APDU.
     *
     * Sends a GET CARD CERTIFICATE command to the card, validates the response,
     * and extracts the ephemeral EC P-256 public key used for ECDH in the secure channel.
     *
     * @param[out] cardEphemeralPubKey Buffer to store the 65-byte card ephemeral public key.
     * @param[in,out] cardEphemeralPubKeyLength Input: size of the buffer; Output: actual key length (65 bytes).
     * @return true if the APDU exchange and key extraction succeeded, false otherwise.
     */
     bool getCardCertificate(uint8_t* cardEphemeralPubKey, uint8_t &cardEphemeralPubKeyLength);
 
     /**
     * @brief Print detailed firmware information of the PN532 module.
     *
     * Retrieves the firmware version, parses IC type, major/minor versions,
     * and supported features, then prints all details to the Serial console.
     *
     * @return true if the PN532 module was detected and information printed, false otherwise.
     */
     bool printPN532FirmwareVersion();
 
     /**
     * @brief Retrieves the initial 32-byte salt from the card for starting a secure channel.
     *
     * This function sends the APDU command to the card to get the session salt, which is
     * required for the subsequent key derivation in the secure channel setup.
     *
     * @param[out] salt Pointer to a 32-byte buffer where the card-provided salt will be stored.
     * @return true if the APDU exchange succeeded and the salt was retrieved, false otherwise.
     */
     bool openSecureChannel(uint8_t* salt, uint8_t* clientPublicKey, uint8_t* clientPrivateKey, const uECC_Curve_t* sessionCurve);
 
     bool mutuallyAuthenticate(CW_SecureSession& session, const uint8_t* salt, uint8_t* clientPublicKey, uint8_t* clientPrivateKey, const uECC_Curve_t* sessionCurve, uint8_t* cardEphemeralPubKey);
 
     /**
     * @brief Extracts the card's ephemeral EC P-256 public key from the certificate.
     *
     * @param[in]  cardCertificate        Pointer to the full card certificate response.
     * @param[out] cardEphemeralPubKey    Buffer to store **64 bytes** (X||Y coordinates only, no 0x04 prefix)
     *                                    for use with uECC_shared_secret. Must be at least 64 bytes.
     * @param[out] fullEphemeralPubKey65  Optional buffer to store **65 bytes** including the 0x04 prefix.
     *                                    Can be nullptr if not needed.
     */
     bool extractCardEphemeralKey(const uint8_t* cardCertificate, uint8_t* cardEphemeralPubKey, uint8_t* fullEphemeralPubKey65 = NULL);
 
     /**
     * @brief Print an APDU in hex format with optional label.
     * @param apdu Pointer to the APDU bytes.
     * @param length Number of bytes in the APDU.
     * @param label Optional label for printing (default: "APDU to send").
     */
     void printApdu(const uint8_t* apdu, uint8_t length, const char* label = "APDU to send");
 
     /**
     * @brief Checks the status word (SW1/SW2) at the end of an APDU response.
     * 
     * @param response        Pointer to the APDU response buffer.
     * @param responseLength  Actual length of the response buffer.
     * @param sw1Expected     Expected value for SW1 (e.g., 0x90).
     * @param sw2Expected     Expected value for SW2 (e.g., 0x00).
     * @return true if the last two bytes match SW1/SW2, false otherwise.
     */
     bool checkStatusWord(const uint8_t* response, uint8_t responseLength, uint8_t sw1Expected, uint8_t sw2Expected);

    /**
    * @brief Encrypts data and sends a secured APDU using AES-CBC and MAC.
    *
    * @param[in,out] session               Reference to the secure session containing keys and IV.
    * @param[in]     apdu                  APDU header (CLA, INS, P1, P2).
    * @param[in]     apduLength            Length of the APDU header.
    * @param[in]     data                  Plaintext data to encrypt and send.
    * @param[in]     dataLength            Length of the plaintext data.
    * @param[out]    decryptedOutput       Optional buffer to receive decrypted response data (nullptr to skip).
    * @param[out]    decryptedOutputLength Optional pointer to receive the decrypted data length (nullptr to skip).
    * @return true if APDU was sent and response decoded successfully, false otherwise.
    */
    bool aes_cbc_encrypt(CW_SecureSession& session, const uint8_t apdu[], uint16_t apduLength,
                         const uint8_t data[], uint16_t dataLength,
                         uint8_t* decryptedOutput = NULL, uint16_t* decryptedOutputLength = NULL);

    /**
    * @brief Verifies the MAC and decrypts an AES-CBC encrypted APDU response.
    *
    * Supports variable-length responses (e.g. card info, DER signatures).
    * MAC is computed over the full ciphertext per SCP03 protocol.
    *
    * @param[in,out] session               Reference to the secure session containing keys and IV.
    * @param[in]     response              Encrypted APDU response buffer (MAC + cipher + SW1/SW2).
    * @param[in]     response_len          Length of the response buffer.
    * @param[in,out] mac_value             MAC from the last sent message (used as decrypt IV; may be modified).
    * @param[out]    decryptedOutput       Optional buffer to receive decrypted data (nullptr to skip).
    * @param[out]    decryptedOutputLength Optional pointer to receive decrypted data length (nullptr to skip).
    * @return true if MAC verification and decryption succeed, false otherwise.
    */
    bool aes_cbc_decrypt(CW_SecureSession& session, uint8_t *response, size_t response_len,
                         uint8_t* mac_value,
                         uint8_t* decryptedOutput = NULL, uint16_t* decryptedOutputLength = NULL);

    /**
     * @brief Check if the secure channel is open.
     *
     * This function checks if the secure channel has been established by verifying
     * if the session keys have been initialized (non-zero). A secure channel is
     * considered open if the AES key in the session is non-zero.
     *
     * @param[in] session Reference to the secure session to check.
     * @return true if the secure channel is open (session keys are initialized), false otherwise.
     */
    bool isSecureChannelOpen(const CW_SecureSession& session) const;

    /* Sign helper methods */
    bool validateSignRequest(const CW_SignRequest& request, CW_SignResult& result);
    void buildSignPayload(const CW_SignRequest& request, uint8_t* data, uint16_t& dataLength);
    bool sendSignApdu(CW_SignRequest& request, const uint8_t* data, uint16_t dataLength,
                      uint8_t* derResponse, uint16_t& derLength, CW_SignResult& result);
    bool extractRawSignature(const uint8_t* derResponse, uint16_t derLength, CW_SignResult& result);
    void debugPrintSignature(const uint8_t* signature);

    /**
     * @brief RNG callback for micro-ecc library.
     * @param dest Pointer to buffer to fill with random bytes.
     * @param size Number of bytes to generate.
     * @return 1 on success.
     */
    static int uECC_RNG(uint8_t *dest, unsigned size);
};

#endif // CRYPTNOXWALLET_H
