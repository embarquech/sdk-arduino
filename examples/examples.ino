/**
 * @file examples.ino
 * @brief Example demonstrating the use of CryptnoxWallet with a PN532 module on Arduino.
 *
 * This sketch initializes the SPI bus and the PN532 NFC reader using the
 * CryptnoxWallet class. It continuously detects NFC/ISO-DEP cards and
 * processes wallet-specific APDU commands with granular step-by-step control.
 */

#include "PN532Adapter.h"
#include "CryptnoxWallet.h"
#include "ArduinoSerialAdapter.h"

/**
 * @def PN532_SS
 * @brief Slave select pin of the PN532 module. Set to -1 if not used.
 */
#define PN532_SS   (10U)

ArduinoSerialAdapter serialAdapter;
PN532Adapter nfc(serialAdapter, PN532_SS, &SPI);
CryptnoxWallet wallet(nfc, serialAdapter);

/**
 * @brief Arduino setup function.
 *
 * Initializes the serial port for debugging and the SPI bus.
 * The PN532 module is initialized via wallet.begin().
 */
void setup() {
    serialAdapter.begin(115200);
    
    /* Arduino R4: Wait 1s to get Serial ready */
    delay(1000);

    /* Initialize SPI bus */
    SPI.begin();

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
 * 2. Verify PIN
 * 3. Get card information
 * 4. Clear session and reset reader
 */
void loop() {
    
    /* Step 1: Connect to card and establish secure channel */
    CW_SecureSession session;
    if (wallet.connect(session)) {
        serialAdapter.println(F("Card connected and secure channel established"));
    
        /* Step 2: Verify PIN (checks secure channel internally) */
        serialAdapter.println(F("Verifying PIN..."));
        wallet.verifyPin(session);
    
        /* Step 3: Get card information (checks secure channel internally) */
        serialAdapter.println(F("Getting card information..."));
        wallet.getCardInfo(session);
    
        serialAdapter.println(F("Card processed successfully"));
    }
    
    /* Always disconnect to reset reader for next card detection */
    wallet.disconnect(session);
    
    /* Wait before next iteration */
    delay(1000);
}
