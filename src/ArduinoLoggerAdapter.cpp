#include "ArduinoLoggerAdapter.h"

ArduinoLoggerAdapter::ArduinoLoggerAdapter()
    : _serial(&Serial) {
}

ArduinoLoggerAdapter::ArduinoLoggerAdapter(HardwareSerial* serial)
    : _serial(serial) {
}

bool ArduinoLoggerAdapter::begin(unsigned long baudRate) {
    _serial->begin(baudRate);
    return true;
}

void ArduinoLoggerAdapter::print(const __FlashStringHelper* str) { _serial->print(str); }
void ArduinoLoggerAdapter::print(const char* str)                 { _serial->print(str); }
void ArduinoLoggerAdapter::print(char c)                          { _serial->print(c); }
void ArduinoLoggerAdapter::print(uint8_t value, int base)         { _serial->print(value, base); }
void ArduinoLoggerAdapter::print(uint16_t value, int base)        { _serial->print(value, base); }
void ArduinoLoggerAdapter::print(uint32_t value, int base)        { _serial->print(value, base); }
void ArduinoLoggerAdapter::print(int value, int base)             { _serial->print(value, base); }

void ArduinoLoggerAdapter::println()                                { _serial->println(); }
void ArduinoLoggerAdapter::println(const __FlashStringHelper* str)  { _serial->println(str); }
void ArduinoLoggerAdapter::println(const char* str)                 { _serial->println(str); }
void ArduinoLoggerAdapter::println(char c)                          { _serial->println(c); }
void ArduinoLoggerAdapter::println(uint8_t value, int base)         { _serial->println(value, base); }
void ArduinoLoggerAdapter::println(uint16_t value, int base)        { _serial->println(value, base); }
void ArduinoLoggerAdapter::println(uint32_t value, int base)        { _serial->println(value, base); }
void ArduinoLoggerAdapter::println(int value, int base)             { _serial->println(value, base); }
