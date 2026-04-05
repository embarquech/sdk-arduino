#include "CryptnoxUtils.h"
#include <trng.h>

/**
 * @brief Constant-time buffer comparison, resistant to timing side-channel attacks.
 */
// cppcheck-suppress unusedFunction
bool CryptnoxUtils::secure_compare(const uint8_t* a, const uint8_t* b, size_t len) {
    uint8_t diff = 0U;
    for (size_t i = 0U; i < len; i++) {
        diff |= a[i] ^ b[i];
    }
    return diff == 0U;
}

/**
 * @brief Securely zero a buffer, guaranteed not to be optimised away.
 */
void CryptnoxUtils::secure_wipe(uint8_t* buf, size_t len) {
    volatile uint8_t* p = buf;
    for (size_t i = 0U; i < len; i++) {
        p[i] = 0U;
    }
}

/**
 * @brief Generate a single cryptographically random byte using the RA4M1 hardware TRNG.
 */
uint8_t CryptnoxUtils::trng_byte() {
    static bool     initialized = false;
    static uint32_t rngBuf      = 0U;
    static uint8_t  rngPos      = 4U; /* 4 => force refill on first call */

    if (!initialized) {
        TRNG.begin();
        initialized = true;
    }
    if (rngPos >= 4U) {
        TRNG.random32(&rngBuf);
        rngPos = 0U;
    }
    const uint8_t b = (uint8_t)((rngBuf >> (rngPos * 8U)) & 0xFFU);
    rngPos++;
    return b;
}
