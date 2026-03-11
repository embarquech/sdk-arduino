#ifndef SERIALDRIVER_H
#define SERIALDRIVER_H
#include <Arduino.h>

/**
 * @class SerialDriver
 * @brief Abstract interface for serial communication.
 *
 * This class provides a hardware-agnostic interface for serial output,
 * allowing different implementations (Arduino Serial, LCD, network logging, etc.)
 * to be used interchangeably by higher-level code like CryptnoxWallet.
 *
 * Implementations must provide all print/println variants used for debug output.
 */
class SerialDriver {
public:
    /**
     * @brief Initialize the serial interface.
     * @param baudRate The baud rate for communication (default: 115200).
     * @return true if initialization succeeded, false otherwise.
     */
    virtual bool begin(unsigned long baudRate = 115200UL) = 0;

    /** @name Print Methods (no newline) */
    ///@{

    /**
     * @brief Print a flash string (F() macro).
     * @param str Flash string to print.
     */
    virtual void print(const __FlashStringHelper* str) = 0;

    /**
     * @brief Print a C-string.
     * @param str Null-terminated string to print.
     */
    virtual void print(const char* str) = 0;

    /**
     * @brief Print a single character.
     * @param c Character to print.
     */
    virtual void print(char c) = 0;

    /**
     * @brief Print an 8-bit unsigned integer.
     * @param value Value to print.
     * @param base Number base (DEC, HEX, BIN, OCT). Default: DEC.
     */
    virtual void print(uint8_t value, int base = DEC) = 0;

    /**
     * @brief Print a 16-bit unsigned integer.
     * @param value Value to print.
     * @param base Number base (DEC, HEX, BIN, OCT). Default: DEC.
     */
    virtual void print(uint16_t value, int base = DEC) = 0;

    /**
     * @brief Print a 32-bit unsigned integer.
     * @param value Value to print.
     * @param base Number base (DEC, HEX, BIN, OCT). Default: DEC.
     */
    virtual void print(uint32_t value, int base = DEC) = 0;

    /**
     * @brief Print a signed integer.
     * @param value Value to print.
     * @param base Number base (DEC, HEX, BIN, OCT). Default: DEC.
     */
    virtual void print(int value, int base = DEC) = 0;

    ///@}

    /** @name Println Methods (with newline) */
    ///@{

    /**
     * @brief Print a newline.
     */
    virtual void println() = 0;

    /**
     * @brief Print a flash string followed by newline.
     * @param str Flash string to print.
     */
    virtual void println(const __FlashStringHelper* str) = 0;

    /**
     * @brief Print a C-string followed by newline.
     * @param str Null-terminated string to print.
     */
    virtual void println(const char* str) = 0;

    /**
     * @brief Print a single character followed by newline.
     * @param c Character to print.
     */
    virtual void println(char c) = 0;

    /**
     * @brief Print an 8-bit unsigned integer followed by newline.
     * @param value Value to print.
     * @param base Number base (DEC, HEX, BIN, OCT). Default: DEC.
     */
    virtual void println(uint8_t value, int base = DEC) = 0;

    /**
     * @brief Print a 16-bit unsigned integer followed by newline.
     * @param value Value to print.
     * @param base Number base (DEC, HEX, BIN, OCT). Default: DEC.
     */
    virtual void println(uint16_t value, int base = DEC) = 0;

    /**
     * @brief Print a 32-bit unsigned integer followed by newline.
     * @param value Value to print.
     * @param base Number base (DEC, HEX, BIN, OCT). Default: DEC.
     */
    virtual void println(uint32_t value, int base = DEC) = 0;

    /**
     * @brief Print a signed integer followed by newline.
     * @param value Value to print.
     * @param base Number base (DEC, HEX, BIN, OCT). Default: DEC.
     */
    virtual void println(int value, int base = DEC) = 0;

    ///@}

    /**
     * @brief Virtual destructor for proper cleanup of derived classes.
     */
    virtual ~SerialDriver() {}
};

#endif // SERIALDRIVER_H

