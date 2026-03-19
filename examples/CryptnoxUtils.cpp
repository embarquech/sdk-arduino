#include "CryptnoxUtils.h"

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
    static bool seeded = false;
    if (seeded == false) {
        randomSeed(analogRead(0U));
        seeded = true;
    }
    return (uint8_t)random(0U, 256U);
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
