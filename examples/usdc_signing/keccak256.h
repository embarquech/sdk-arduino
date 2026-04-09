/**
 * @file keccak256.h
 * @brief Keccak-256 (SHA3 variant) hash function for Ethereum.
 *
 * Provides a function to compute the Keccak-256 hash of an input buffer,
 * producing a 32-byte digest.
 *
 * @note This implementation is suitable for Ethereum-style hashing.
 */

#ifndef KECCAK256_H
#define KECCAK256_H

#include <stdint.h>
#include <stddef.h>

/**
 * @brief Compute the Keccak-256 hash of a given input buffer.
 *
 * @param[in]  in     Pointer to input data.
 * @param[in]  inlen  Length of input data in bytes.
 * @param[out] out    Pointer to a 32-byte buffer where the hash will be stored.
 *
 * @note The output buffer must be at least 32 bytes long.
 * @note This function implements the Ethereum variant of Keccak-256.
 */
void keccak256(const uint8_t *in, size_t inlen, uint8_t out[32]);

#endif /* KECCAK256_H */