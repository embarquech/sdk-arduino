/**
 * @file keccak256.cpp
 * @brief Keccak-256 (SHA3 variant) hash implementation for Ethereum.
 *
 * Implements Keccak-256 hashing suitable for Ethereum-style hashing,
 * producing a 32-byte digest. This file contains the internal
 * permutation function and the main keccak256 API.
 */

#include "keccak256.h"
#include <string.h>

// Number of rounds for the Keccak-f[1600] permutation
#define KECCAK_ROUNDS 24

// Round constants for Keccak-f[1600]
static const uint64_t keccakf_rndc[24] = {
  0x0000000000000001ULL, 0x0000000000008082ULL,
  0x800000000000808aULL, 0x8000000080008000ULL,
  0x000000000000808bULL, 0x0000000080000001ULL,
  0x8000000080008081ULL, 0x8000000000008009ULL,
  0x000000000000008aULL, 0x0000000000000088ULL,
  0x0000000080008009ULL, 0x000000008000000aULL,
  0x000000008000808bULL, 0x800000000000008bULL,
  0x8000000000008089ULL, 0x8000000000008003ULL,
  0x8000000000008002ULL, 0x8000000000000080ULL,
  0x000000000000800aULL, 0x800000008000000aULL,
  0x8000000080008081ULL, 0x8000000000008080ULL,
  0x0000000080000001ULL, 0x8000000080008008ULL
};

/**
 * @brief Rotate a 64-bit integer left by s bits.
 *
 * @param x Value to rotate.
 * @param s Number of bits to rotate.
 * @return Rotated value.
 */
static inline uint64_t rol(uint64_t x, int s) { return (x << s) | (x >> (64 - s)); }

/**
 * @brief Keccak-f[1600] permutation on the state array.
 *
 * @param st 25-word state array (1600 bits).
 *
 * This function applies the 24-round Keccak-f permutation on the
 * input state array in-place.
 */
static void keccakf(uint64_t st[25]) {
  for (int r = 0; r < KECCAK_ROUNDS; ++r) {
    uint64_t bc[5];
    for (int i = 0; i < 5; ++i)
      bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];

    for (int i = 0; i < 5; ++i) {
      uint64_t t = bc[(i + 4) % 5] ^ rol(bc[(i + 1) % 5], 1);
      for (int j = 0; j < 25; j += 5)
        st[j + i] ^= t;
    }

    uint64_t t = st[1];
    for (int i = 0; i < 24; ++i) {
      uint64_t j = 0;
      static const int keccakf_rotc[24] = {
        1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
        27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44
      };
      static const int keccakf_piln[24] = {
        10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
        15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1
      };
      j = keccakf_piln[i];
      uint64_t tmp = st[j];
      st[j] = rol(t, keccakf_rotc[i]);
      t = tmp;
    }

    for (int j = 0; j < 25; j += 5) {
      uint64_t bc0 = st[j];
      uint64_t bc1 = st[j+1];
      uint64_t bc2 = st[j+2];
      uint64_t bc3 = st[j+3];
      uint64_t bc4 = st[j+4];
      
      st[j]   ^= (~bc1) & bc2;
      st[j+1] ^= (~bc2) & bc3;
      st[j+2] ^= (~bc3) & bc4;
      st[j+3] ^= (~bc4) & bc0;
      st[j+4] ^= (~bc0) & bc1;
    }
    st[0] ^= keccakf_rndc[r];
  }
}

/**
 * @brief Compute Keccak-256 hash of input data.
 *
 * @param[in]  in     Pointer to input buffer.
 * @param[in]  inlen  Length of input buffer in bytes.
 * @param[out] out    Pointer to a 32-byte buffer to store the hash.
 *
 * @note The output buffer must be at least 32 bytes long.
 * @note This is Ethereum's Keccak-256 (pre-SHA3 standard padding).
 */
// cppcheck-suppress unusedFunction
void keccak256(const uint8_t *in, size_t inlen, uint8_t out[32]) {
  uint64_t st[25];
  memset(st, 0, sizeof(st));

  size_t rate = 1088/8; // SHA3-256 rate in bytes

  // Absorb full rate blocks
  while (inlen >= rate) {
    for (size_t i = 0; i < rate/8; ++i) {
      uint64_t t = 0;
      memcpy(&t, in + i*8, 8);
      st[i] ^= t;
    }
    keccakf(st);
    inlen -= rate;
    in += rate;
  }

  // Absorb remaining bytes and pad
  uint8_t temp[200];
  memset(temp, 0, sizeof(temp));
  memcpy(temp, in, inlen);
  temp[inlen] = 0x01;       // Ethereum Keccak-256 padding
  temp[rate-1] |= 0x80;

  for (size_t i = 0; i < rate/8; ++i) {
    uint64_t t = 0;
    memcpy(&t, temp + i*8, 8);
    st[i] ^= t;
  }
  keccakf(st);

  // Copy first 32 bytes of state as hash output
  memcpy(out, st, 32);
}
