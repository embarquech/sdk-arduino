#include "ArduinoCryptoProvider.h"
#include "CryptnoxUtils.h"
#if CW_VERIFY_CERT
#include <SHA256.h>
#endif
#include <SHA512.h>
#include <AES.h>
#include "uECC.h"

/**
 * @brief Constructor. Registers the TRNG-backed RNG with micro-ecc.
 */
ArduinoCryptoProvider::ArduinoCryptoProvider() {
    uECC_set_rng(&ArduinoCryptoProvider::trngCallback);
}

/**
 * @brief Static RNG callback for uECC_set_rng().
 */
int ArduinoCryptoProvider::trngCallback(uint8_t* dest, unsigned size) {
    int ret = 0;
    if ((dest != NULL) && (size > 0U)) {
        for (unsigned i = 0U; i < size; i++) {
            dest[i] = CryptnoxUtils::trng_byte();
        }
        ret = 1;
    }
    return ret;
}

/**
 * @brief Compute SHA-256 over a contiguous data buffer.
 */
void ArduinoCryptoProvider::sha256(const uint8_t* data, size_t len, uint8_t* out) {
#if CW_VERIFY_CERT
    SHA256 sha;
    sha.update(data, len);
    sha.finalize(out, 32U);
#else
    (void)data; (void)len; (void)out; /* SHA-256 disabled: CW_VERIFY_CERT=0 */
#endif
}

/**
 * @brief Compute SHA-512 over a contiguous data buffer.
 */
void ArduinoCryptoProvider::sha512(const uint8_t* data, size_t len, uint8_t* out) {
    SHA512 sha;
    sha.update(data, len);
    sha.finalize(out, 64U);
}

/**
 * @brief AES-CBC encrypt.
 */
uint16_t ArduinoCryptoProvider::aesCbcEncrypt(const uint8_t* in, uint16_t len, uint8_t* out,
                                               const uint8_t* key, uint8_t keyLen,
                                               uint8_t* iv, bool bitPadding) {
    _aes.set_paddingmode(bitPadding ? paddingMode::Bit : paddingMode::Null);
    return _aes.encrypt(reinterpret_cast<const byte*>(in), len, out,
                        reinterpret_cast<const byte*>(key), static_cast<int>(keyLen), iv);
}

/**
 * @brief AES-CBC decrypt.
 */
uint16_t ArduinoCryptoProvider::aesCbcDecrypt(uint8_t* in, uint16_t len, uint8_t* out,
                                               const uint8_t* key, uint8_t keyLen,
                                               uint8_t* iv, bool bitPadding) {
    _aes.set_paddingmode(bitPadding ? paddingMode::Bit : paddingMode::Null);
    return _aes.decrypt(in, len, out,
                        reinterpret_cast<const byte*>(key), static_cast<int>(keyLen), iv);
}

/**
 * @brief ECDH shared secret computation.
 */
bool ArduinoCryptoProvider::ecdh(const uint8_t* pubKey, const uint8_t* privKey,
                                  uint8_t* secret, const uECC_Curve_t* curve) {
    return (uECC_shared_secret(pubKey, privKey, secret, curve) != 0);
}

/**
 * @brief Generate a new EC key pair.
 */
bool ArduinoCryptoProvider::makeKey(uint8_t* pubKey, uint8_t* privKey,
                                     const uECC_Curve_t* curve) {
    return (uECC_make_key(pubKey, privKey, curve) != 0);
}

/**
 * @brief Fill a buffer with random bytes from the hardware TRNG.
 */
bool ArduinoCryptoProvider::random(uint8_t* dest, unsigned size) {
    return (trngCallback(dest, size) == 1);
}
