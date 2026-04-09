/**
 * @file usdc_signing.ino
 * @brief Send an ERC20 USDC transaction on Ethereum (EIP-1559) via Arduino,
 *        signed on-device using a Cryptnox smart card over NFC (PN532).
 *
 * Demonstrates:
 * - Connecting to WiFi
 * - RLP encoding of an unsigned and signed EIP-1559 transaction
 * - Keccak-256 hashing
 * - Signing the transaction hash with a Cryptnox card via PN532
 * - Determining yParity via the Ethereum ecrecover precompile (eth_call)
 * - Sending the signed transaction via JSON-RPC
 */

#include <Arduino.h>
#include <SPI.h>
#include <WiFi.h>
#include "keccak256.h"
#include <WiFiS3.h>
#include <ArduinoHttpClient.h>
#include "util.h"
#include "config.h"
#include <PN532Adapter.h>
#include <CryptnoxWallet.h>
#include <ArduinoLoggerAdapter.h>
#include <ArduinoCryptoProvider.h>
#include <CryptnoxUtils.h>

/** @brief PN532 SPI slave-select pin. */
#define PN532_SS_PIN  (10U)

/* Fallback PIN — define CARD_PIN and CARD_PIN_LEN in config.h to override. */
#ifndef CARD_PIN
#  define CARD_PIN     "000000000"
#  define CARD_PIN_LEN (9U)
#endif

ArduinoLoggerAdapter serialAdapter;
ArduinoCryptoProvider cryptoProvider;
PN532Adapter nfc(serialAdapter, PN532_SS_PIN, &SPI);
CryptnoxWallet wallet(nfc, serialAdapter, cryptoProvider);

/** ERC-20 transfer(address,uint256) function selector: keccak256("transfer(address,uint256)")[0..3] */
#define ERC20_TRANSFER_SEL_0  0xa9U
#define ERC20_TRANSFER_SEL_1  0x05U
#define ERC20_TRANSFER_SEL_2  0x9cU
#define ERC20_TRANSFER_SEL_3  0xbbU

#define ERC20_INDEX_OFFSET 64U

/** @brief Sentinel returned by determineYParity() when recovery fails. */
#define YPARITY_UNKNOWN 0xFFU

/** @brief Expected HTTP 200 OK status code. */
#define HTTP_OK 200

/** @brief Maximum number of send-transaction attempts before giving up. */
#define TX_MAX_RETRIES       3U
/** @brief Delay in ms between send-transaction retry attempts. */
#define TX_RETRY_DELAY_MS 2000U
/** @brief Maximum WiFi reconnect poll iterations (each iteration waits 500 ms). */
#define WIFI_RETRY_MAX      20U
/** @brief Buffer size for a two-hex-char + NUL string used in byte-to-hex conversion. */
#define HEX_CHAR_BUF_SIZE    3U
/** @brief Number of leading zero hex characters in the ecrecover v-field padding. */
#define ECRECOVER_V_PAD_CHARS 62U
/** @brief Base value for Ethereum ecrecover v parameter (yParity=0 → v=27, yParity=1 → v=28). */
#define ECRECOVER_V_BASE    27U

/**
 * @brief Ethereum EIP-1559 transaction structure.
 */
struct Tx2 {
    uint64_t nonce;                 /**< Transaction nonce */
    uint64_t maxPriorityFeePerGas;  /**< Max priority fee (wei) */
    uint64_t maxFeePerGas;          /**< Max fee (wei) */
    uint64_t gasLimit;              /**< Gas limit */
    const char* to;                 /**< Recipient address */
    uint64_t value;                 /**< Value in wei */
    const uint8_t* data;            /**< Transaction calldata */
    size_t dataLen;                 /**< Length of calldata */
    uint32_t chainId;               /**< Ethereum chain ID */
};

/**
 * @brief Encode unsigned EIP-1559 transaction into RLP.
 * @param tx Transaction structure
 * @param out Output buffer
 * @return Total RLP size
 */
size_t rlpEncodeUnsignedTx(const Tx2 &tx, uint8_t *out) {
    uint8_t buf[1024];
    size_t off = 0;
    uint8_t tmp[8];
    size_t tmpLen;

    tmpLen = ConvertNumberToUintArray(tmp, tx.chainId);
    off += RlpEncodeItem(buf + off, tmp, tmpLen);

    tmpLen = ConvertNumberToUintArray(tmp, tx.nonce);
    off += RlpEncodeItem(buf + off, tmp, tmpLen);

    tmpLen = ConvertNumberToUintArray(tmp, tx.maxPriorityFeePerGas);
    off += RlpEncodeItem(buf + off, tmp, tmpLen);

    tmpLen = ConvertNumberToUintArray(tmp, tx.maxFeePerGas);
    off += RlpEncodeItem(buf + off, tmp, tmpLen);

    tmpLen = ConvertNumberToUintArray(tmp, tx.gasLimit);
    off += RlpEncodeItem(buf + off, tmp, tmpLen);

    uint8_t addr[20];
    hexToBytes(tx.to, addr, 20);
    off += RlpEncodeItem(buf + off, addr, 20);

    tmpLen = ConvertNumberToUintArray(tmp, tx.value);
    off += RlpEncodeItem(buf + off, tmp, tmpLen);

    off += RlpEncodeItem(buf + off, tx.data, tx.dataLen);

    buf[off++] = 0xC0; /* empty AccessList */

    uint8_t header[8];
    size_t header_len = RlpEncodeWholeHeader(header, off);

    size_t out_off = 0U;
    out[out_off++] = 0x02; /* EIP-1559 type prefix */
    memcpy(out + out_off, header, header_len);
    out_off += header_len;
    memcpy(out + out_off, buf, off);
    out_off += off;

    return out_off;
}

/**
 * @brief Encode signed EIP-1559 transaction into RLP.
 * @param tx  Unsigned transaction
 * @param r   Signature r component (32 bytes)
 * @param s   Signature s component (32 bytes)
 * @param v   yParity (1 byte: 0 or 1)
 * @param out Output buffer
 * @return Total RLP size
 */
size_t rlpEncodeSignedTx(const Tx2& tx, const uint8_t* r, const uint8_t* s, const uint8_t* v, uint8_t* out) {
    uint8_t buf[1024];
    size_t off = 0;
    uint8_t tmp[8];
    size_t tmp_len;

    tmp_len = ConvertNumberToUintArray(tmp, tx.chainId);
    off += RlpEncodeItem(buf + off, tmp, tmp_len);

    tmp_len = ConvertNumberToUintArray(tmp, tx.nonce);
    off += RlpEncodeItem(buf + off, tmp, tmp_len);

    tmp_len = ConvertNumberToUintArray(tmp, tx.maxPriorityFeePerGas);
    off += RlpEncodeItem(buf + off, tmp, tmp_len);

    tmp_len = ConvertNumberToUintArray(tmp, tx.maxFeePerGas);
    off += RlpEncodeItem(buf + off, tmp, tmp_len);

    tmp_len = ConvertNumberToUintArray(tmp, tx.gasLimit);
    off += RlpEncodeItem(buf + off, tmp, tmp_len);

    uint8_t addr[20];
    hexToBytes(tx.to, addr, 20);
    off += RlpEncodeItem(buf + off, addr, 20);

    tmp_len = ConvertNumberToUintArray(tmp, tx.value);
    off += RlpEncodeItem(buf + off, tmp, tmp_len);

    off += RlpEncodeItem(buf + off, tx.data, tx.dataLen);

    buf[off++] = 0xC0; /* empty AccessList */

    off += RlpEncodeItem(buf + off, v, 1U);

    uint8_t tmp_r[32];
    tmp_len = trimLeadingZeros(tmp_r, r, 32U);
    off += RlpEncodeItem(buf + off, tmp_r, tmp_len);

    uint8_t tmp_s[32];
    tmp_len = trimLeadingZeros(tmp_s, s, 32U);
    off += RlpEncodeItem(buf + off, tmp_s, tmp_len);

    uint8_t header[8];
    size_t header_len = RlpEncodeWholeHeader(header, off);

    size_t out_off = 0U;
    out[out_off++] = 0x02;
    memcpy(out + out_off, header, header_len);
    out_off += header_len;
    memcpy(out + out_off, buf, off);
    out_off += off;

    return out_off;
}

/**
 * @brief Encode calldata for ERC-20 transfer(address to, uint256 amount).
 * @param out Output buffer (at least 68 bytes)
 * @return Calldata length (always 68)
 */
size_t encodeERC20Transfer(uint8_t* out) {
    out[0] = ERC20_TRANSFER_SEL_0; /* transfer(address,uint256) selector byte 0 */
    out[1] = ERC20_TRANSFER_SEL_1; /* transfer(address,uint256) selector byte 1 */
    out[2] = ERC20_TRANSFER_SEL_2; /* transfer(address,uint256) selector byte 2 */
    out[3] = ERC20_TRANSFER_SEL_3; /* transfer(address,uint256) selector byte 3 */
    CryptnoxUtils::secure_wipe(out+4,  12U); /* bytes  4-15: ABI word padding before address (12 zero bytes) */
    hexToBytes(ADDR_TO, out+16, 20); /* bytes 16-35: recipient address (20 bytes)           */
    CryptnoxUtils::secure_wipe(out+36, 28U); /* bytes 36-63: ABI word padding before amount  (28 zero bytes) */
    out[ERC20_INDEX_OFFSET]   = (uint8_t)((AMOUNT_USDC >> 24U) & 0xFFU);
    out[ERC20_INDEX_OFFSET+1] = (uint8_t)((AMOUNT_USDC >> 16U) & 0xFFU);
    out[ERC20_INDEX_OFFSET+2] = (uint8_t)((AMOUNT_USDC >> 8U)  & 0xFFU);
    out[ERC20_INDEX_OFFSET+3] = (uint8_t)( AMOUNT_USDC         & 0xFFU);
    return 68;
}

/**
 * @brief Send a raw signed transaction via JSON-RPC.
 * @param raw Signed transaction bytes
 * @param len Length of raw transaction in bytes
 */
void sendRawTx(const uint8_t* raw, size_t len) {
    static const char hexC[] = "0123456789abcdef";
    static const char kPfx[] =
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_sendRawTransaction\","
        "\"params\":[\"0x";
    static const char kSfx[] = "\"]}";
    for (uint8_t attempt = 0U; attempt < TX_MAX_RETRIES; attempt++) {
        if (attempt != 0U) {
            delay(TX_RETRY_DELAY_MS);
        }
        if (WiFi.status() != WL_CONNECTED) {
            Serial.println(F("sendRawTx: WiFi not connected, reconnecting..."));
            WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
            uint8_t wifiRetry = 0U;
            while ((WiFi.status() != WL_CONNECTED) && (wifiRetry < WIFI_RETRY_MAX)) {
                delay(500U);
                wifiRetry++;
            }
            if (WiFi.status() != WL_CONNECTED) {
                Serial.println(F("sendRawTx: WiFi reconnect failed"));
                continue;
            }
        }
        WiFiSSLClient wifiClient;
        HttpClient client(wifiClient, RPC_HOST, RPC_PORT);
        if (wifiClient.connect(RPC_HOST, RPC_PORT) == 0) {
            Serial.println(F("sendRawTx: failed to connect to RPC host."));
            continue;
        }
        client.beginRequest();
        int err = client.post("/");
        if (err != HTTP_SUCCESS) {
            Serial.println(F("sendRawTx: POST failed."));
            client.stop();
            continue;
        }
        client.sendHeader("Content-Type", "application/json");
        client.sendHeader("Content-Length",
            (int)(sizeof(kPfx)-1) + 2*(int)len + (int)(sizeof(kSfx)-1));
        client.beginBody();
        client.print(kPfx);
        char hexByte[HEX_CHAR_BUF_SIZE];
        hexByte[2] = '\0'; /* two hex chars + NUL for each byte of raw tx */
        for (size_t i = 0; i < len; i++) {
            hexByte[0] = hexC[raw[i] >> 4];  /* high nibble */
            hexByte[1] = hexC[raw[i] & 0x0f]; /* low nibble */
            client.print(hexByte);
        }
        client.print(kSfx);
        client.endRequest();
        int status = client.responseStatusCode();
        bool txSent = (status > 0);
        client.stop();
        if (txSent) {
            break;
        }
    }
}

/**
 * @brief Determine EIP-1559 yParity by calling the Ethereum ecrecover precompile.
 *
 * Tries v=27 (yParity=0) and v=28 (yParity=1). Compares the recovered address
 * with ADDR_FROM (defined in config.h) to pick the correct value.
 *
 * @param hash    Keccak-256 transaction hash (32 bytes).
 * @param r       Signature r component (32 bytes).
 * @param s       Signature s component (32 bytes).
 * @return 0 or 1 on success, YPARITY_UNKNOWN on failure.
 */
uint8_t determineYParity(const uint8_t* hash, const uint8_t* r, const uint8_t* s) {
    static const char hexChars[] = "0123456789abcdef";
    /* ecrecover calldata: "0x" + hash(64) + v(64) + r(64) + s(64) = 258 chars + NUL */
    char hexBuf[260];
    uint16_t pos = 0U;
    hexBuf[pos++] = '0';
    hexBuf[pos++] = 'x';
    for (uint8_t i = 0U; i < 32U; i++) {
        hexBuf[pos++] = hexChars[hash[i] >> 4];
        hexBuf[pos++] = hexChars[hash[i] & 0x0f];
    }
    /* v field: ECRECOVER_V_PAD_CHARS zero chars, then 1 value byte — filled per iteration */
    const uint16_t vOffset = pos;
    for (uint8_t i = 0U; i < ECRECOVER_V_PAD_CHARS; i++) {
        hexBuf[pos++] = '0';
    }
    pos += 2U; /* placeholder for v byte */
    for (uint8_t i = 0U; i < 32U; i++) {
        hexBuf[pos++] = hexChars[r[i] >> 4];
        hexBuf[pos++] = hexChars[r[i] & 0x0f];
    }
    for (uint8_t i = 0U; i < 32U; i++) {
        hexBuf[pos++] = hexChars[s[i] >> 4];
        hexBuf[pos++] = hexChars[s[i] & 0x0f];
    }
    hexBuf[pos] = '\0'; /* pos == 258 */

    static const char kPrefix[] =
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_call\","
        "\"params\":[{\"to\":\"0x0000000000000000000000000000000000000001\","
        "\"data\":\"";
    static const char kSuffix[] = "\"},\"latest\"]}";
    const int bodyLen = (int)(sizeof(kPrefix) - 1) + 258 + (int)(sizeof(kSuffix) - 1);

    uint8_t result = YPARITY_UNKNOWN;
    for (uint8_t yp = 0U; (yp <= 1U) && (result == YPARITY_UNKNOWN); yp++) {
        /* Patch v byte into last two chars of the v field.
         * Ethereum ecrecover: v=27 means yParity=0, v=28 means yParity=1. */
        const uint8_t v = ECRECOVER_V_BASE + yp;
        hexBuf[vOffset + ECRECOVER_V_PAD_CHARS]      = hexChars[(v & 0xFFU) >> 4U];
        hexBuf[vOffset + ECRECOVER_V_PAD_CHARS + 1U] = hexChars[(v & 0xFFU) & 0x0FU];

        if (WiFi.status() != WL_CONNECTED) {
            Serial.println(F("determineYParity: WiFi not connected, reconnecting..."));
            WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
            uint8_t wifiRetry = 0U;
            while ((WiFi.status() != WL_CONNECTED) && (wifiRetry < WIFI_RETRY_MAX)) {
                delay(500U);
                wifiRetry++;
            }
            if (WiFi.status() != WL_CONNECTED) {
                Serial.println(F("determineYParity: WiFi reconnect failed"));
                continue;
            }
        }
        WiFiSSLClient wifiClient;
        HttpClient client(wifiClient, RPC_HOST, RPC_PORT);
        if (wifiClient.connect(RPC_HOST, RPC_PORT) == 0) {
            Serial.println(F("determineYParity: failed to connect to RPC host."));
            continue;
        }
        client.beginRequest();
        int err = client.post("/");
        if (err != HTTP_SUCCESS) {
            Serial.println(F("determineYParity: POST failed."));
            client.stop();
            continue;
        }
        client.sendHeader("Content-Type", "application/json");
        client.sendHeader("Content-Length", bodyLen);
        client.beginBody();
        client.print(kPrefix);
        client.print(hexBuf);
        client.print(kSuffix);
        client.endRequest();

        int status = client.responseStatusCode();
        String response = client.responseBody(); /* consume response body */
        client.stop();
        if (status != HTTP_OK) {
            continue;
        }
        int resultIdx = response.indexOf("\"result\"");
        if (resultIdx < 0) {
            continue;
        }
        int hexIdx = response.indexOf("0x", resultIdx);
        if (hexIdx < 0) {
            continue;
        }
        /* ecrecover returns 32-byte word; address = last 20 bytes = last 40 hex chars */
        String recovered = response.substring(hexIdx + 26, hexIdx + 66);
        if (recovered.equalsIgnoreCase(ADDR_FROM)) {
            result = yp;
        }
    }
    return result;
}

/**
 * @brief Fetch the current nonce for ADDR_FROM via eth_getTransactionCount.
 * @param nonce Output: nonce value on success (note: 0 is a valid nonce for a fresh address).
 * @return 0 on success, 1 on failure.
 */
uint8_t fetchNonce(uint64_t* nonce) {
    static const char kPfx[] =
        "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"eth_getTransactionCount\","
        "\"params\":[\"0x";
    static const char kSfx[] = "\",\"pending\"]}";
    const int bodyLen = (int)(sizeof(kPfx)-1) + 40 + (int)(sizeof(kSfx)-1);

    uint8_t result = 1U;
    for (uint8_t attempt = 0U; (attempt < TX_MAX_RETRIES) && (result != 0U); attempt++) {
        if (attempt != 0U) {
            delay(1000U);
        }
        if (WiFi.status() != WL_CONNECTED) {
            Serial.println(F("fetchNonce: WiFi not connected, reconnecting..."));
            WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
            uint8_t wifiRetry = 0U;
            while ((WiFi.status() != WL_CONNECTED) && (wifiRetry < WIFI_RETRY_MAX)) {
                delay(500U);
                wifiRetry++;
            }
            if (WiFi.status() != WL_CONNECTED) {
                Serial.println(F("fetchNonce: WiFi reconnect failed"));
                continue;
            }
        }
        WiFiSSLClient wifiClient;
        HttpClient client(wifiClient, RPC_HOST, RPC_PORT);
        if (wifiClient.connect(RPC_HOST, RPC_PORT) == 0) {
            Serial.println(F("fetchNonce: failed to connect to RPC host."));
            continue;
        }
        client.beginRequest();
        int err = client.post("/");
        if (err != HTTP_SUCCESS) {
            Serial.println(F("fetchNonce: POST failed."));
            client.stop();
            continue;
        }
        client.sendHeader("Content-Type", "application/json");
        client.sendHeader("Content-Length", bodyLen);
        client.beginBody();
        client.print(kPfx);
        client.print(ADDR_FROM);
        client.print(kSfx);
        client.endRequest();

        int status = client.responseStatusCode();
        String resp = client.responseBody();
        client.stop();
        if (status == HTTP_OK) {
            int ri = resp.indexOf("\"result\"");
            int xi = (ri >= 0) ? resp.indexOf("0x", ri) : -1;
            if (xi >= 0) {
                uint64_t parsed = 0U;
                for (int i = xi + 2; i < (int)resp.length(); i++) {
                    char c = resp[i];
                    if (!((c>='0'&&c<='9')||(c>='a'&&c<='f')||(c>='A'&&c<='F'))) break;
                    parsed = (parsed << 4) | fromHex(c);
                }
                *nonce = parsed;
                result = 0U;
            }
        }
    }
    return result;
}

/**
 * @brief Arduino setup: init PN532, connect WiFi, build tx, sign with Cryptnox card, send.
 */
void setup() {
    Serial.begin(115200);
    delay(2000);

    /* Init SPI and PN532 */
    SPI.begin();
    if (!wallet.begin()) {
        Serial.println(F("PN532 init failed! Halting."));
        while(1);
    }
    Serial.println(F("PN532 OK"));

    /* Connect to WiFi */
    Serial.print(F("Connecting to WiFi"));
    WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
    uint8_t retries = 20U;
    while ((WiFi.status() != WL_CONNECTED) && retries--) {
        delay(500U);
        Serial.print(F("."));
    }
    Serial.println();
    if (WiFi.status() != WL_CONNECTED) {
        Serial.println(F("WiFi failed!"));
        while(1);
    }
    delay(2000); /* Allow network stack to stabilise before first SSL connection */

    /* Build ERC-20 calldata */
    uint8_t calldata[68];
    size_t calLen = encodeERC20Transfer(calldata);

    /* Build unsigned EIP-1559 transaction */
    Tx2 tx2;
    uint64_t fetchedNonce = 0U;
    if (fetchNonce(&fetchedNonce) != 0U) {
        Serial.println(F("fetchNonce failed! Halting."));
        while(1);
    }
    tx2.nonce              = fetchedNonce;
    tx2.maxPriorityFeePerGas = MAX_PRIORITY_FEE;
    tx2.maxFeePerGas       = MAX_FEE;
    tx2.gasLimit           = GAS_LIMIT_ERC20;
    tx2.to                 = ADDR_USDC;
    tx2.value              = 0;
    tx2.data               = calldata;
    tx2.dataLen            = calLen;
    tx2.chainId            = CHAIN_ID_SEPOLIA;

    /* RLP encode unsigned tx */
    uint8_t rlpUnsigned[512];
    size_t rlpLen = rlpEncodeUnsignedTx(tx2, rlpUnsigned);

    /* Keccak-256 hash */
    uint8_t hashKeccak[32];
    keccak256(static_cast<const uint8_t*>(rlpUnsigned), rlpLen, hashKeccak);

    /* === Sign with Cryptnox card over NFC (with retry on NFC dropout) === */
    Serial.println(F("Place Cryptnox card on PN532 reader..."));
    CW_SignResult signResult;
    for (uint8_t attempt = 0U; attempt < 3U; attempt++) {
        if (attempt != 0U) {
            delay(1000U);
        }
        CW_SecureSession session;
        if (!wallet.connect(session)) {
            continue;
        }
        Serial.println(F("Card connected, secure channel established."));

        CW_SignRequest signReq(session, CW_SIGN_CURR_K1, CW_SIGN_SIG_ECDSA_LOW_S, CW_SIGN_WITH_PIN);
        signReq.hash       = hashKeccak;
        signReq.hashLength = CW_HASH_SIZE;
        memcpy(signReq.pin, CARD_PIN, CARD_PIN_LEN);

        signResult = wallet.sign(signReq);
        wallet.disconnect(session);
        if (signResult.errorCode == CW_OK) {
            break;
        }
        Serial.print(F("Sign attempt "));
        Serial.print(attempt + 1U);
        Serial.println(F(" failed."));
    }

    if (signResult.errorCode != CW_OK) {
        Serial.print(F("Sign failed: 0x"));
        Serial.println(signResult.errorCode, HEX);
        while(1);
    }
    Serial.println(F("Signed."));

    const uint8_t* r = signResult.signature;       /* first 32 bytes */
    const uint8_t* s = signResult.signature + 32;  /* last  32 bytes */

    /* Determine yParity */
    uint8_t yParity = determineYParity(hashKeccak, r, s);
    if (yParity == YPARITY_UNKNOWN) {
        Serial.println(F("yParity determination failed! Halting."));
        while(1);
    }
    Serial.print(F("yParity: "));
    Serial.println(yParity);

    /* RLP encode signed tx and send */
    uint8_t rlpSigned[512];
    size_t rlpSignedLen = rlpEncodeSignedTx(tx2, r, s, &yParity, rlpSigned);

    Serial.println(F("Sending..."));
    sendRawTx(rlpSigned, rlpSignedLen);
}

/**
 * @brief Arduino loop (empty — transaction is sent once in setup).
 */
void loop() {}
