#include "CryptnoxUtils.h"
#include <TRNG.h>

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
    static bool     initialized = false;
    static uint32_t rngBuf      = 0U;
    static uint8_t  rngPos      = 4U; /* 4 => force refill on first call */

    if (!initialized) {
        TRNG.begin();
        initialized = true;
    }
    if (rngPos >= 4U) {
        TRNG.random(rngBuf);
        rngPos = 0U;
    }
    const uint8_t b = (uint8_t)((rngBuf >> (rngPos * 8U)) & 0xFFU);
    rngPos++;
    return b;
}

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
