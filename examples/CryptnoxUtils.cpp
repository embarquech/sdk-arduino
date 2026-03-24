#include "CryptnoxUtils.h"

/**
 * @brief Constant-time buffer comparison, resistant to timing side-channel attacks.
 * @param a   Pointer to the first buffer.
 * @param b   Pointer to the second buffer.
 * @param len Number of bytes to compare.
 * @return true if the buffers are identical, false otherwise.
 */
// cppcheck-suppress unusedFunction
bool CryptnoxUtils::secure_compare(const uint8_t* a, const uint8_t* b, size_t len) {
    uint8_t diff = 0U;
    for (size_t i = 0U; i < len; i++) {
        diff |= a[i] ^ b[i];
    }
    return diff == 0U;
}

// cppcheck-suppress unusedFunction
void CryptnoxUtils::secure_wipe(uint8_t* buf, size_t len) {
    volatile uint8_t* p = buf;
    for (size_t i = 0U; i < len; i++) {
        p[i] = 0U;
    }
}

uint8_t CryptnoxUtils::trng_byte() {
    static bool seeded = false;
    if (seeded == false) {
        randomSeed(analogRead(0U));
        seeded = true;
    }
    return (uint8_t)random(0U, 256U);
}

/**
 * @brief RNG callback compatible with uECC_set_rng().
 *
 * Fills dest with size random bytes by calling trng_byte() repeatedly.
 *
 * @param dest Pointer to the buffer to fill.
 * @param size Number of bytes to generate.
 * @return 1 on success, 0 if dest is NULL or size is 0.
 */
// cppcheck-suppress unusedFunction
int CryptnoxUtils::uECC_rng_callback(uint8_t* dest, unsigned size) {
    int ret = 0;

    if ((dest != NULL) && (size > 0U)) {
        for (unsigned i = 0U; i < size; i++) {
            dest[i] = trng_byte();
        }
        ret = 1;
    }

    return ret;
}
