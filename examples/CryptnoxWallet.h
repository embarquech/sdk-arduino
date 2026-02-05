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
    * The function first detects if an ISO-DEP capable card is present, then establishes a secure channel.
    * It first detects if an ISO-DEP capable card is present, then establishes a secure channel
    * by selecting the Cryptnox application, retrieving the card certificate, performing ECDH key
    * exchange, and mutually authenticating with the card.
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
    * @brief Verifies the PIN code.
    * @param[in,out] session Reference to the secure session containing keys and IV.
    */
    void verifyPin(CW_SecureSession& session);

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
     bool extractCardEphemeralKey(const uint8_t* cardCertificate, uint8_t* cardEphemeralPubKey, uint8_t* fullEphemeralPubKey65 = nullptr);
 
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
    * @param[in,out] session    Reference to the secure session containing keys and IV.
    * @param[in] apdu           APDU header (CLA, INS, P1, P2).
    * @param[in] apduLength     Length of the APDU header.
    * @param[in] data           Plaintext data to encrypt and send.
    * @param[in] dataLength     Length of the plaintext data.
    */
    void aes_cbc_encrypt(CW_SecureSession& session, const uint8_t apdu[], uint16_t apduLength, const uint8_t data[], uint16_t dataLength);

    /**
    * @brief Decrypts data from a secured APDU using AES-CBC and verifies the MAC.
    *
    * @param[in,out] session      Reference to the secure session containing keys and IV.
    * @param[in,out] response     Encrypted APDU response buffer (decrypted in place).
    * @param[in]     response_len Length of the response buffer.
    * @param[out]    mac_value    Computed MAC value.
    * @return true if MAC verification succeeds, false otherwise.
    */
    bool aes_cbc_decrypt(CW_SecureSession& session, uint8_t *response, size_t response_len, uint8_t * mac_value);

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

    /**
     * @brief RNG callback for micro-ecc library.
     * @param dest Pointer to buffer to fill with random bytes.
     * @param size Number of bytes to generate.
     * @return 1 on success.
     */
    static int uECC_RNG(uint8_t *dest, unsigned size);
};

#endif // CRYPTNOXWALLET_H
