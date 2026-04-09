// Created by Okada, Takahiro on 2018/02/11.

#include <Arduino.h>
#include "util.h"

/**
 * @brief Convert a hexadecimal character to a byte value.
 * @param c Hex character
 * @return Binary value (0-15)
 */
uint8_t fromHex(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return 0;
}

/**
 * @brief Convert a hex string to a byte array.
 * @param hex Input hex string
 * @param out Output byte array
 * @param len Number of bytes to convert
 */
// cppcheck-suppress unusedFunction
void hexToBytes(const char* hex, uint8_t* out, size_t len) {
    for (size_t i = 0; i < len; i++) {
        out[i] = (fromHex(hex[2*i]) << 4) | fromHex(hex[2*i+1]);
    }
}

/**
 * @brief Encodes the RLP list header for a sequence of items.
 *
 * This function generates the RLP "whole header" for a list payload of length total_len,
 * according to Ethereum RLP specification.
 *
 * RLP encoding rules:
 * - For a list with total payload < 55 bytes:
 *   0xC0 + total_len (single-byte header)
 * - For a list with payload >= 55 bytes:
 *   0xF7 + length_of_length_field, followed by the big-endian encoded total_len
 *
 * Example:
 * total_len = 10 → header = C0 + 0x0A → C0 0A
 * total_len = 100 → total_len = 0x64 (1 byte) → F8 64
 * total_len = 1024 → total_len = 0x0400 (2 bytes) → F9 04 00
 *
 * This header is intended to be placed immediately before the concatenated items
 * in an RLP list. For EIP-1559 typed transactions, it must appear after the type byte (0x02).
 *
 * @param[out] header_output Pointer where the encoded header will be written.
 * @param[in] total_len Length in bytes of all list items concatenated.
 * @return Number of bytes written to header_output.
 */
// cppcheck-suppress unusedFunction
uint32_t RlpEncodeWholeHeader(uint8_t* header_output, uint32_t total_len)
{
    if (total_len < 55U)
    {
        header_output[0] = (uint8_t)0xc0 + (uint8_t)total_len;
        return 1U;
    }
    else
    {
        uint8_t tmp_header[8];
        memset(tmp_header, 0, 8U);
        uint32_t hexdigit = 1U;
        uint32_t tmp = total_len;
        while ((uint32_t)(tmp / 256U) > 0U)
        {
            tmp_header[hexdigit] = (uint8_t)(tmp % 256U);
            tmp = (uint32_t)(tmp / 256U);
            hexdigit++;
        }
        tmp_header[hexdigit] = (uint8_t)(tmp);
        tmp_header[0] = (uint8_t)0xf7 + (uint8_t)hexdigit;

        // fix direction for header
        uint8_t header[8];
        memset(header, 0, 8U);
        header[0] = tmp_header[0];
        for (uint32_t i = 0U; i < hexdigit; i++)
        {
            header[i + 1U] = tmp_header[hexdigit - i];
        }
        memcpy(header_output, header, (size_t)hexdigit + 1U);
        return hexdigit + 1U;
    }
}

/**
 * @brief Encodes a single RLP item.
 *
 * @param[out] output Buffer where the encoded RLP item will be written.
 * @param[in] input Input data to encode.
 * @param[in] input_len Length of input data.
 * @return Number of bytes written to output.
 */
// cppcheck-suppress unusedFunction
uint32_t RlpEncodeItem(uint8_t* output, const uint8_t* input, uint32_t input_len)
{
    if (input_len == 1U && input[0] == 0x00U)
    {
        const uint8_t c[1] = {0x80};
        memcpy(output, c, 1U);
        return 1U;
    }
    else if (input_len == 1U && input[0] < 128U)
    {
        memcpy(output, input, 1U);
        return 1U;
    }
    else if (input_len <= 55U)
    {
        const uint8_t _ = (uint8_t)0x80 + (uint8_t)input_len;
        const uint8_t header[] = {_};
        memcpy(output, header, 1U);
        memcpy(output + 1U, input, (size_t)input_len);
        return input_len + 1U;
    }
    else
    {
        uint8_t tmp_header[8];
        memset(tmp_header, 0, 8U);
        uint32_t hexdigit = 1U;
        uint32_t tmp = input_len;
        while ((uint32_t)(tmp / 256U) > 0U)
        {
            tmp_header[hexdigit] = (uint8_t)(tmp % 256U);
            tmp = (uint32_t)(tmp / 256U);
            hexdigit++;
        }
        tmp_header[hexdigit] = (uint8_t)(tmp);
        tmp_header[0] = (uint8_t)0xb7 + (uint8_t)hexdigit;

        // fix direction for header
        uint8_t header[8];
        memset(header, 0, 8U);
        header[0] = tmp_header[0];
        for (uint32_t i = 0U; i < hexdigit; i++)
        {
            header[i + 1U] = tmp_header[hexdigit - i];
        }
        memcpy(output, header, hexdigit + 1U);
        memcpy(output + hexdigit + 1U, input, (size_t)input_len);
        return input_len + hexdigit + 1U;
    }
}

/**
 * @brief Converts a 32-bit number into a big-endian byte array.
 *
 * @param[out] str Output buffer.
 * @param[in] val Unsigned 32-bit integer to convert.
 * @return Number of bytes written to the buffer.
 */
// cppcheck-suppress unusedFunction
uint32_t ConvertNumberToUintArray(uint8_t* str, uint32_t val)
{
    uint32_t ret = 0U;
    uint8_t tmp[8];
    memset(tmp, 0, 8U);

    while ((uint32_t)(val / 256U) > 0U)
    {
        tmp[ret] = (uint8_t)(val % 256U);
        val = (uint32_t)(val / 256U);
        ret++;
    }
    tmp[ret] = (uint8_t)(val % 256U);
    for (uint32_t i = 0U; i < ret + 1U; i++)
    {
        str[i] = tmp[ret - i];
    }

    return ret + 1U;
}

/**
 * @brief Trims leading zeros from a byte array.
 *
 * @param[out] out Output buffer.
 * @param[in] in Input buffer.
 * @param[in] in_len Length of input buffer.
 * @return Number of bytes written to the output buffer.
 */
// cppcheck-suppress unusedFunction
size_t trimLeadingZeros(uint8_t* out, const uint8_t* in, size_t in_len)
{
    size_t start = 0;
    while (start < in_len - 1 && in[start] == 0)
    {
        start++;
    }
    size_t len = in_len - start;
    memcpy(out, in + start, len);
    return len;
}
