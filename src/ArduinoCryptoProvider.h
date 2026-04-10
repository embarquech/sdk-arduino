#ifndef ARDUINOCRYPTOPROVIDER_H
#define ARDUINOCRYPTOPROVIDER_H

/******************************************************************
 * 1. Included files
 ******************************************************************/

#include <Arduino.h>
#include "CW_CryptoProvider.h"
#include "AESLib.h"

/******************************************************************
 * 2. Class declaration
 ******************************************************************/

/**
 * @class ArduinoCryptoProvider
 * @brief Concrete CW_CryptoProvider implementation for Arduino (RA4M1).
 *
 * Wraps:
 *  - AESLib     for AES-CBC encrypt / decrypt
 *  - SHA512     (Crypto library) for SHA-512 hashing
 *  - micro-ecc  for ECDH shared secret and EC key generation
 *  - RA4M1 TRNG (via CryptnoxUtils::trng_byte) for random byte generation
 *
 * The constructor registers the internal static RNG callback with
 * micro-ecc (uECC_set_rng) so callers never need to do this manually.
 */
class ArduinoCryptoProvider : public CW_CryptoProvider {
public:
    /**
     * @brief Constructor. Registers the TRNG callback with uECC_set_rng().
     */
    ArduinoCryptoProvider();

    ArduinoCryptoProvider(const ArduinoCryptoProvider&) = delete;
    ArduinoCryptoProvider& operator=(const ArduinoCryptoProvider&) = delete;

    /** @name CW_CryptoProvider interface */
    ///@{
    void sha256(const uint8_t* data, size_t len, uint8_t* out) override;

    void sha512(const uint8_t* data, size_t len, uint8_t* out) override;

    uint16_t aesCbcEncrypt(const uint8_t* in, uint16_t len, uint8_t* out,
                           const uint8_t* key, uint8_t keyLen,
                           uint8_t* iv, bool bitPadding) override;

    uint16_t aesCbcDecrypt(uint8_t* in, uint16_t len, uint8_t* out,
                           const uint8_t* key, uint8_t keyLen,
                           uint8_t* iv, bool bitPadding) override;

    bool ecdh(const uint8_t* pubKey, const uint8_t* privKey,
              uint8_t* secret, const uECC_Curve_t* curve) override;

    bool makeKey(uint8_t* pubKey, uint8_t* privKey,
                 const uECC_Curve_t* curve) override;

    bool random(uint8_t* dest, unsigned size) override;
    ///@}

private:
    AESLib _aes; ///< AES-CBC engine (AESLib library).

    /**
     * @brief Static RNG callback compatible with uECC_set_rng().
     *
     * Fills dest with size random bytes via CryptnoxUtils::trng_byte().
     *
     * @param dest Buffer to fill.
     * @param size Number of bytes to generate.
     * @return 1 on success, 0 on error.
     */
    static int trngCallback(uint8_t* dest, unsigned size);
};

#endif // ARDUINOCRYPTOPROVIDER_H
