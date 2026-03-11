#include "ArduinoSerialAdapter.h"

/**
 * @brief Construct an ArduinoSerialAdapter using the default Serial.
 */
ArduinoSerialAdapter::ArduinoSerialAdapter()
    : _serial(&Serial) {
}

/**
 * @brief Construct an ArduinoSerialAdapter using a specific HardwareSerial.
 * @param serial Pointer to the HardwareSerial instance to use.
 */
ArduinoSerialAdapter::ArduinoSerialAdapter(HardwareSerial* serial)
    : _serial(serial) {
}

/**
 * @brief Initialize the serial interface.
 * @param baudRate The baud rate for communication.
 * @return true (Arduino Serial.begin() doesn't return a status).
 */
bool ArduinoSerialAdapter::begin(unsigned long baudRate) {
    _serial->begin(baudRate);
    return true;
}

/* Print methods (no newline) */

void ArduinoSerialAdapter::print(const __FlashStringHelper* str) {
    _serial->print(str);
}

void ArduinoSerialAdapter::print(const char* str) {
    _serial->print(str);
}

void ArduinoSerialAdapter::print(char c) {
    _serial->print(c);
}

void ArduinoSerialAdapter::print(uint8_t value, int base) {
    _serial->print(value, base);
}

void ArduinoSerialAdapter::print(uint16_t value, int base) {
    _serial->print(value, base);
}

void ArduinoSerialAdapter::print(uint32_t value, int base) {
    _serial->print(value, base);
}

void ArduinoSerialAdapter::print(int value, int base) {
    _serial->print(value, base);
}

/* Println methods (with newline) */

void ArduinoSerialAdapter::println() {
    _serial->println();
}

void ArduinoSerialAdapter::println(const __FlashStringHelper* str) {
    _serial->println(str);
}

void ArduinoSerialAdapter::println(const char* str) {
    _serial->println(str);
}

void ArduinoSerialAdapter::println(char c) {
    _serial->println(c);
}

void ArduinoSerialAdapter::println(uint8_t value, int base) {
    _serial->println(value, base);
}

void ArduinoSerialAdapter::println(uint16_t value, int base) {
    _serial->println(value, base);
}

void ArduinoSerialAdapter::println(uint32_t value, int base) {
    _serial->println(value, base);
}

void ArduinoSerialAdapter::println(int value, int base) {
    _serial->println(value, base);
}

