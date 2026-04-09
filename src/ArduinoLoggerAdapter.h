#ifndef ARDUINOLOGGERADAPTER_H
#define ARDUINOLOGGERADAPTER_H

/******************************************************************
 * 1. Included files
 ******************************************************************/

#include <Arduino.h>
#include "CW_Logger.h"

/******************************************************************
 * 2. Class declaration
 ******************************************************************/

/**
 * @class ArduinoLoggerAdapter
 * @brief Concrete implementation of CW_Logger wrapping Arduino's HardwareSerial.
 *
 * Allows CryptnoxWallet and CW_SecureChannel to use the standard Arduino
 * Serial interface through the CW_Logger abstraction. By default it wraps
 * the primary Serial object, but any HardwareSerial instance can be used.
 *
 * @example
 * @code
 * ArduinoLoggerAdapter logger;           // Uses Serial
 * ArduinoLoggerAdapter logger1(&Serial1); // Uses Serial1
 * @endcode
 */
class ArduinoLoggerAdapter : public CW_Logger {
public:
    /**
     * @brief Construct using the default Serial.
     */
    ArduinoLoggerAdapter();

    /**
     * @brief Construct using a specific HardwareSerial instance.
     * @param serial Pointer to the HardwareSerial to use.
     */
    explicit ArduinoLoggerAdapter(HardwareSerial* serial);

    ~ArduinoLoggerAdapter() override = default;

    ArduinoLoggerAdapter(const ArduinoLoggerAdapter&) = delete;
    ArduinoLoggerAdapter& operator=(const ArduinoLoggerAdapter&) = delete;

    /** @name CW_Logger interface implementation */
    ///@{
    bool begin(unsigned long baudRate = 115200UL) override;

    void print(const __FlashStringHelper* str) override;
    void print(const char* str) override;
    void print(char c) override;
    void print(uint8_t value, int base = DEC) override;
    void print(uint16_t value, int base = DEC) override;
    void print(uint32_t value, int base = DEC) override;
    void print(int value, int base = DEC) override;

    void println() override;
    void println(const __FlashStringHelper* str) override;
    void println(const char* str) override;
    void println(char c) override;
    void println(uint8_t value, int base = DEC) override;
    void println(uint16_t value, int base = DEC) override;
    void println(uint32_t value, int base = DEC) override;
    void println(int value, int base = DEC) override;
    ///@}

private:
    HardwareSerial* _serial; ///< Pointer to the underlying HardwareSerial instance.
};

#endif // ARDUINOLOGGERADAPTER_H
