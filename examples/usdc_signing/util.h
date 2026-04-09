//
// Created by Okada, Takahiro on 2018/02/11.
//

#ifndef UTIL_H
#define UTIL_H

#include <stdint.h>
#include <stddef.h>

/**
 * @brief Encodes the total length into an RLP list header.
 *
 * This function generates the RLP header for a list of items with a given total length.
 *
 * @param[out] header_output Pointer to buffer to store the RLP header.
 * @param[in]  total_len Total length of the RLP list content.
 * @return Number of bytes written into header_output.
 */
uint32_t RlpEncodeWholeHeader(uint8_t *header_output, uint32_t total_len);

/**
 * @brief Encodes a single item in RLP format.
 *
 * @param[out] output Pointer to buffer to store the RLP-encoded item.
 * @param[in]  input Pointer to the data to encode.
 * @param[in]  input_len Length of the input data in bytes.
 * @return Number of bytes written into output.
 */
uint32_t RlpEncodeItem(uint8_t* output, const uint8_t* input, uint32_t input_len);

/**
 * @brief Converts a 32-bit unsigned integer to a byte array.
 *
 * @param[out] str Pointer to output buffer.
 * @param[in]  val Unsigned integer to convert.
 * @return Number of bytes used in the output array.
 */
uint32_t ConvertNumberToUintArray(uint8_t *str, uint32_t val);

/**
 * @brief Removes leading zeros from a byte array.
 *
 * @param[out] out Pointer to buffer to store trimmed result.
 * @param[in]  in Pointer to input byte array.
 * @param[in]  in_len Length of input array.
 * @return Number of bytes written into out (length of trimmed array).
 */
size_t trimLeadingZeros(uint8_t* out, const uint8_t* in, size_t in_len);

/**
 * @brief Convert a hexadecimal character to a byte value.
 * @param c Hex character
 * @return Binary value (0-15)
 */
uint8_t fromHex(char c);

/**
 * @brief Convert a hex string to a byte array.
 * @param hex Input hex string
 * @param out Output byte array
 * @param len Number of bytes to convert
 */
void hexToBytes(const char* hex, uint8_t* out, size_t len);

#endif /* UTIL_H */
