#ifndef ARDUINOSERIALADAPTER_H
#define ARDUINOSERIALADAPTER_H

#include <Arduino.h>
#include "SerialDriver.h"

/**
 * @class ArduinoSerialAdapter
 * @brief Concrete implementation of SerialDriver wrapping Arduino's HardwareSerial.
 *
 * This adapter allows CryptnoxWallet and other components to use the standard
 * Arduino Serial interface through the SerialDriver abstraction. By default,
 * it wraps the primary Serial object, but can be configured to use any
 * HardwareSerial instance (Serial1, Serial2, etc.).
 *
 * @example
 * @code
 * ArduinoSerialAdapter serialAdapter;           // Uses Serial
 * ArduinoSerialAdapter serialAdapter1(&Serial1); // Uses Serial1
 * @endcode
 */
class ArduinoSerialAdapter : public SerialDriver {
public:
    /**
     * @brief Construct an ArduinoSerialAdapter using the default Serial.
     */
    ArduinoSerialAdapter();

    /**
     * @brief Construct an ArduinoSerialAdapter using a specific HardwareSerial.
     * @param serial Pointer to the HardwareSerial instance to use.
     */
    explicit ArduinoSerialAdapter(HardwareSerial* serial);

    /**
     * @brief Destructor.
     */
    ~ArduinoSerialAdapter() override = default;

    /**
     * @brief Deleted copy constructor to prevent copying.
     */
    ArduinoSerialAdapter(const ArduinoSerialAdapter&) = delete;

    /**
     * @brief Deleted copy assignment operator to prevent assignment.
     */
    ArduinoSerialAdapter& operator=(const ArduinoSerialAdapter&) = delete;

    /** @name SerialDriver Interface Implementation */
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

#endif // ARDUINOSERIALADAPTER_H

