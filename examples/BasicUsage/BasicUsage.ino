/**
 * @file BasicUsage.ino
 * @brief Example demonstrating the use of CryptnoxWallet with a PN532 module on Arduino.
 *
 * This sketch initializes the PN532 NFC reader using the CryptnoxWallet class.
 * It continuously detects NFC/ISO-DEP cards and processes wallet-specific APDU
 * commands with granular step-by-step control.
 *
 * Select the communication interface by defining USE_SPI or USE_I2C below.
 */

#include <CryptnoxSDK.h>

/* ============================================================================
 * 1. Interface Selection
 * --------------------------------------------------------------------------
 * Uncomment exactly ONE of the two lines below to choose the PN532 interface.
 * ========================================================================= */
// #define USE_SPI
#define USE_I2C

/* ============================================================================
 * 2. Pin Configuration
 * ========================================================================= */
#if defined(USE_SPI)

#include <SPI.h>

/**
 * @def PN532_SS
 * @brief SPI slave select (CS) pin for the PN532 module.
 */
#define PN532_SS    (10U)

ArduinoLoggerAdapter serialAdapter;
PN532Adapter nfc(serialAdapter, PN532_SS, &SPI);

#elif defined(USE_I2C)

#include <Wire.h>

/**
 * @def PN532_IRQ
 * @brief IRQ pin of the PN532 module for I2C communication.
 */
#define PN532_IRQ   (2U)

/**
 * @def PN532_RST
 * @brief Reset pin of the PN532 module.
 */
#define PN532_RST   (3U)

ArduinoLoggerAdapter serialAdapter;
PN532Adapter nfc(serialAdapter, PN532_IRQ, PN532_RST, &Wire);

#else
#error "Please define USE_SPI or USE_I2C to select the PN532 interface."
#endif

/** @brief Default PIN code (ASCII digits). Must match the PIN used during card.init(). */
#define DEFAULT_PIN       "000000000"
#define DEFAULT_PIN_LEN   (sizeof(DEFAULT_PIN) - 1U)

ArduinoCryptoProvider cryptoProvider;
CryptnoxWallet wallet(nfc, serialAdapter, cryptoProvider);

/**
 * @brief Arduino setup function.
 *
 * Initializes the serial port for debugging, the selected bus,
 * and the PN532 module.
 */
void setup() {
    serialAdapter.begin(115200);

    /* Arduino R4: Wait 1s to get Serial ready */
    delay(1000);

#if defined(USE_SPI)
    /* Initialize SPI bus */
    SPI.begin();
#elif defined(USE_I2C)
    /* Initialize I2C bus */
    Wire.begin();
#endif

    /* Initialize the PN532 module */
    if (wallet.begin()) {
        serialAdapter.println(F("PN532 initialized"));
    } else {
        serialAdapter.println(F("PN532 init failed"));
        /* Halt program if initialization fails */
        while(1);
    }
}

/**
 * @brief Arduino main loop.
 *
 * Demonstrates simplified card connection and processing:
 * 1. Connect to card and establish secure channel (combines detection and channel setup)
 * 2. Sign a test hash (PIN included in sign payload)
 * 3. Clear session and reset reader
 */
void loop() {

    /* Step 1: Connect to card and establish secure channel */
    CW_SecureSession session;
    if (wallet.connect(session)) {
        serialAdapter.println(F("Card connected and secure channel established"));

        /* Step 2: Sign a test hash (32 bytes of 0x01 for demo purposes) */
        /* NOTE: Card must have a seed loaded (via Python SDK: card.generate_seed(pin) */
        /*       or card.load_seed(seed, pin)) before signing will work.              */
        serialAdapter.println(F("Signing test hash..."));
        uint8_t testHash[CW_HASH_SIZE];
        memset(testHash, 0x01, sizeof(testHash));

        /* Build sign request per CW_SignRequest API.
         * PIN is included in the sign data payload for authentication.
         * Alternatively, call verifyPin() first and omit the PIN here. */
        CW_SignRequest signRequest(session, CW_SIGN_CURR_K1, CW_SIGN_SIG_ECDSA_LOW_S, CW_SIGN_WITH_PIN);
        signRequest.hash = testHash;
        signRequest.hashLength = sizeof(testHash);
        /* Set PIN (must match the PIN used during card.init()) */
        CryptnoxUtils::safe_memcpy(signRequest.pin, sizeof(signRequest.pin),
                                    (const uint8_t*)DEFAULT_PIN, DEFAULT_PIN_LEN);

        CW_SignResult signResult = wallet.sign(signRequest);

        if (signResult.errorCode == CW_OK) {
            serialAdapter.println(F("Signature received (64 bytes raw r||s)"));

            /* Print first 8 bytes of R and S for quick visual check */
            serialAdapter.print(F("  R[0..7]: "));
            for (uint8_t i = CW_SIG_R_OFFSET; i < CW_SIG_R_OFFSET + 8U; i++) {
                if (signResult.signature[i] < 0x10U) serialAdapter.print(F("0"));
                serialAdapter.print(signResult.signature[i], HEX);
                serialAdapter.print(F(" "));
            }
            serialAdapter.println();
            serialAdapter.print(F("  S[0..7]: "));
            for (uint8_t i = CW_SIG_S_OFFSET; i < CW_SIG_S_OFFSET + 8U; i++) {
                if (signResult.signature[i] < 0x10U) serialAdapter.print(F("0"));
                serialAdapter.print(signResult.signature[i], HEX);
                serialAdapter.print(F(" "));
            }
            serialAdapter.println();
            serialAdapter.println(F("Card processed successfully"));
        } else {
            serialAdapter.print(F("Sign failed, errorCode: 0x"));
            serialAdapter.println(signResult.errorCode, HEX);
        }

        /* Securely wipe sensitive buffers */
        CryptnoxUtils::secure_wipe(testHash, sizeof(testHash));
        CryptnoxUtils::secure_wipe(signResult.signature, sizeof(signResult.signature));
    }

    /* Always disconnect to reset reader for next card detection */
    wallet.disconnect(session);

    /* Wait before next iteration */
    delay(1000);
}
