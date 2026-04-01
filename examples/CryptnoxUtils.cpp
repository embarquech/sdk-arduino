#include "CryptnoxUtils.h"
#ifndef STATIC_ANALYSIS
#  include <trng.h>
#endif

bool CryptnoxUtils::secure_compare(const uint8_t* a, const uint8_t* b, size_t len) {
    uint8_t diff = 0U;
    for (size_t i = 0U; i < len; i++) {
        diff |= a[i] ^ b[i];
    }
    return diff == 0U;
}

void CryptnoxUtils::secure_wipe(uint8_t* buf, size_t len) {
    volatile uint8_t* p = buf;
    for (size_t i = 0U; i < len; i++) {
        p[i] = 0U;
    }
}

uint8_t CryptnoxUtils::trng_byte() {
#ifndef STATIC_ANALYSIS
    static bool initialized = false;
    if (!initialized) {
        TRNG.begin();
        initialized = true;
    }
    uint8_t b = 0U;
    if (!TRNG.random8(&b)) {
        Serial.println(F("TRNG.random8 failed"));
    }
    return b;
#else
    return 0U; /* stub for static analysis — TRNG not available */
#endif
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
