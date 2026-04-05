/**
 * @file CryptnoxSDK.h
 * @brief Umbrella include for the CryptnoxSDK Arduino library.
 *
 * Include this single header to pull in all library components:
 *   - CW_NfcTransport / CW_Logger       (abstract interfaces)
 *   - CW_CryptoProvider                 (abstract crypto interface)
 *   - CW_Defs                           (session struct + constants)
 *   - CW_SecureChannel                  (secure channel protocol)
 *   - ArduinoLoggerAdapter              (concrete serial logger)
 *   - ArduinoCryptoProvider             (concrete crypto implementation)
 *   - PN532Adapter                      (concrete NFC implementation)
 *   - CryptnoxWallet                    (high-level card API)
 *   - CryptnoxUtils                     (secure compare, wipe, TRNG)
 *
 * @example
 * @code
 * #include <CryptnoxSDK.h>
 * @endcode
 */
#pragma once

#include "CW_Defs.h"
#include "CW_NfcTransport.h"
#include "CW_Logger.h"
#include "CW_CryptoProvider.h"
#include "CW_SecureChannel.h"
#include "ArduinoLoggerAdapter.h"
#include "ArduinoCryptoProvider.h"
#include "PN532Adapter.h"
#include "CryptnoxWallet.h"
#include "CryptnoxUtils.h"
