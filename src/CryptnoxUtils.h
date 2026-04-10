#ifndef CRYPTNOX_UTILS_H
#define CRYPTNOX_UTILS_H

/******************************************************************
 * 1. Included files
 ******************************************************************/

#include <Arduino.h>

/******************************************************************
 * 2. Class declaration
 ******************************************************************/

/**
 * @class CryptnoxUtils
 * @brief Utility functions for cryptographic and security operations.
 *
 * Provides constant-time comparisons, secure memory wiping, and
 * true random number generation for use across the SDK.
 */
class CryptnoxUtils {
public:
    /**
     * @brief Constant-time buffer comparison, resistant to timing side-channel attacks.
     *
     * Always iterates over the full length regardless of where the first difference
     * occurs, preventing an attacker from inferring the correct value byte-by-byte
     * via timing measurements.
     *
     * @param a   Pointer to the first buffer.
     * @param b   Pointer to the second buffer.
     * @param len Number of bytes to compare.
     * @return true if the buffers are identical, false otherwise.
     */
    static bool secure_compare(const uint8_t* a, const uint8_t* b, size_t len);

    /**
     * @brief Securely zero a buffer, guaranteed not to be optimised away.
     *
     * Uses a volatile pointer so the compiler cannot elide the writes,
     * ensuring sensitive material is actually erased from memory.
     *
     * @param buf Pointer to the buffer to wipe.
     * @param len Number of bytes to zero.
     */
    static void secure_wipe(uint8_t* buf, size_t len);

    /**
     * @brief Bounds-checked memcpy — validates pointers, count, and non-overlap before copying.
     *
     * @param dst     Destination buffer pointer.
     * @param dstSize Capacity of the destination buffer in bytes.
     * @param src     Source buffer pointer.
     * @param count   Number of bytes to copy.
     * @return true if the copy succeeded, false if any argument is invalid or buffers overlap.
     */
    static bool safe_memcpy(uint8_t* dst, size_t dstSize, const uint8_t* src, size_t count);

    /**
     * @brief Generate a single cryptographically random byte using the RA4M1 hardware TRNG.
     *
     * Initialises the hardware TRNG on first call. Consumes one 32-bit hardware
     * random word per 4 calls to avoid wasting entropy.
     *
     * @return A random byte in [0, 255].
     */
    static uint8_t trng_byte();

    /**
     * @brief Bounds-checked memcpy — validates pointers, count, and non-overlap before copying.
     *
     * @param dst     Destination buffer pointer.
     * @param dstSize Capacity of the destination buffer in bytes.
     * @param src     Source buffer pointer.
     * @param count   Number of bytes to copy.
     * @return true if the copy succeeded, false if any argument is invalid or buffers overlap.
     */
    static bool safe_memcpy(uint8_t* dst, size_t dstSize, const uint8_t* src, size_t count);
};

#endif // CRYPTNOX_UTILS_H
