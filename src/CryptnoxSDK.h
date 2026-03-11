/**
 * @file CryptnoxSDK.h
 * @brief Umbrella include for the CryptnoxSDK Arduino library.
 *
 * Include this single header to pull in all library components:
 *   - NFCDriver / SerialDriver  (abstract interfaces)
 *   - ArduinoSerialAdapter      (concrete serial implementation)
 *   - PN532Adapter              (concrete NFC implementation)
 *   - CryptnoxWallet            (high-level card API)
 *
 * @example
 * @code
 * #include <CryptnoxSDK.h>
 * @endcode
 */
#pragma once

#include "NFCDriver.h"
#include "SerialDriver.h"
#include "ArduinoSerialAdapter.h"
#include "PN532Adapter.h"
#include "CryptnoxWallet.h"
