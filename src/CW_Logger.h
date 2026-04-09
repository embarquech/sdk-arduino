#ifndef CW_LOGGER_H
#define CW_LOGGER_H

/******************************************************************
 * 1. Included files
 ******************************************************************/

#include <Arduino.h>

/******************************************************************
 * 2. Class declaration
 ******************************************************************/

/**
 * @class CW_Logger
 * @brief Abstract interface for serial/debug output.
 *
 * Provides a hardware-agnostic logging contract so that higher-level
 * components (CryptnoxWallet, CW_SecureChannel) remain independent
 * of the physical output device (UART, LCD, network, etc.).
 *
 * Implementations must provide all print/println variants used
 * throughout the SDK for debug output.
 */
class CW_Logger {
public:
    /**
     * @brief Initialize the logging interface.
     * @param baudRate Baud rate (relevant for UART implementations).
     * @return true if initialization succeeded, false otherwise.
     */
    virtual bool begin(unsigned long baudRate = 115200UL) = 0;

    /** @name Print methods (no newline) */
    ///@{
    virtual void print(const __FlashStringHelper* str) = 0;
    virtual void print(const char* str) = 0;
    virtual void print(char c) = 0;
    virtual void print(uint8_t value, int base = DEC) = 0;
    virtual void print(uint16_t value, int base = DEC) = 0;
    virtual void print(uint32_t value, int base = DEC) = 0;
    virtual void print(int value, int base = DEC) = 0;
    ///@}

    /** @name Println methods (with newline) */
    ///@{
    virtual void println() = 0;
    virtual void println(const __FlashStringHelper* str) = 0;
    virtual void println(const char* str) = 0;
    virtual void println(char c) = 0;
    virtual void println(uint8_t value, int base = DEC) = 0;
    virtual void println(uint16_t value, int base = DEC) = 0;
    virtual void println(uint32_t value, int base = DEC) = 0;
    virtual void println(int value, int base = DEC) = 0;
    ///@}

    virtual ~CW_Logger() {}
};

#endif // CW_LOGGER_H
