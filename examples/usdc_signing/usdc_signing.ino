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
#include <ArduinoSerialAdapter.h>

/** @brief PN532 SPI slave-select pin. */
#define PN532_SS_PIN  (10U)

/* Fallback PIN — define CARD_PIN and CARD_PIN_LEN in config.h to override. */
#ifndef CARD_PIN
#  define CARD_PIN     "000000000"
#  define CARD_PIN_LEN (9U)
#endif

ArduinoSerialAdapter serialAdapter;
PN532Adapter nfc(serialAdapter, PN532_SS_PIN, &SPI);
CryptnoxWallet wallet(nfc, serialAdapter);

#define ERC20_INDEX_OFFSET 64U

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
void hexToBytes(const char* hex, uint8_t* out, size_t len) {
    for (size_t i = 0; i < len; i++) {
        out[i] = (fromHex(hex[2*i]) << 4) | fromHex(hex[2*i+1]);
    }
}

/**
 * @brief Print a byte array as hex to Serial.
 * @param d Data array
 * @param l Length
 */
void printHex(const uint8_t* d, size_t l) {
    for (size_t i = 0; i < l; i++) {
        if (d[i] < 0x10) Serial.print('0');
        Serial.print(d[i], HEX);
    }
    Serial.println();
}

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

    size_t out_off = 0;
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
    tmp_len = trimLeadingZeros(tmp_r, r, 32);
    off += RlpEncodeItem(buf + off, tmp_r, tmp_len);

    uint8_t tmp_s[32];
    tmp_len = trimLeadingZeros(tmp_s, s, 32);
    off += RlpEncodeItem(buf + off, tmp_s, tmp_len);

    uint8_t header[8];
    size_t header_len = RlpEncodeWholeHeader(header, off);

    size_t out_off = 0;
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
    out[0]=0xa9; out[1]=0x05; out[2]=0x9c; out[3]=0xbb; /* transfer() selector */
    memset(out+4, 0, 12);
    hexToBytes(ADDR_TO, out+16, 20);
    memset(out+36, 0, 28);
    out[ERC20_INDEX_OFFSET]   = (AMOUNT_USDC >> 24) & 0xFF;
    out[ERC20_INDEX_OFFSET+1] = (AMOUNT_USDC >> 16) & 0xFF;
    out[ERC20_INDEX_OFFSET+2] = (AMOUNT_USDC >> 8)  & 0xFF;
    out[ERC20_INDEX_OFFSET+3] =  AMOUNT_USDC        & 0xFF;
    return 68;
}

/**
 * @brief Send a raw signed transaction via JSON-RPC.
 * @param rawHex Hex-encoded signed transaction (without 0x prefix)
 */
void sendRawTx(const uint8_t* raw, size_t len) {
    static const char hexC[] = "0123456789abcdef";
    static const char kPfx[] =
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_sendRawTransaction\","
        "\"params\":[\"0x";
    static const char kSfx[] = "\"]}";
    for (uint8_t attempt = 0; attempt < 3; attempt++) {
        if (attempt) delay(2000);
        WiFiSSLClient wifiClient;
        HttpClient client(wifiClient, RPC_HOST, RPC_PORT);
        client.beginRequest();
        client.post("/");
        client.sendHeader("Content-Type", "application/json");
        client.sendHeader("Content-Length",
            (int)(sizeof(kPfx)-1) + 2*(int)len + (int)(sizeof(kSfx)-1));
        client.beginBody();
        client.print(kPfx);
        char b[3]; b[2] = '\0';
        for (size_t i = 0; i < len; i++) {
            b[0] = hexC[raw[i] >> 4];
            b[1] = hexC[raw[i] & 0x0f];
            client.print(b);
        }
        client.print(kSfx);
        client.endRequest();
        int status = client.responseStatusCode();
        Serial.print(F("Status:")); Serial.println(status);
        if (status > 0) { Serial.println(client.responseBody()); client.stop(); return; }
        client.stop();
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
 * @return 0 or 1 on success, 0xFF on failure.
 */
uint8_t determineYParity(const uint8_t* hash, const uint8_t* r, const uint8_t* s) {
    static const char hexChars[] = "0123456789abcdef";
    /* ecrecover calldata: "0x" + hash(64) + v(64) + r(64) + s(64) = 258 chars + NUL */
    char hexBuf[260];
    int pos = 0;
    hexBuf[pos++] = '0';
    hexBuf[pos++] = 'x';
    for (int i = 0; i < 32; i++) {
        hexBuf[pos++] = hexChars[hash[i] >> 4];
        hexBuf[pos++] = hexChars[hash[i] & 0x0f];
    }
    /* v field: 31 zero bytes (62 '0' chars) then 1 value byte — filled per iteration */
    const int vOffset = pos;
    for (int i = 0; i < 62; i++) hexBuf[pos++] = '0';
    pos += 2; /* placeholder for v byte */
    for (int i = 0; i < 32; i++) {
        hexBuf[pos++] = hexChars[r[i] >> 4];
        hexBuf[pos++] = hexChars[r[i] & 0x0f];
    }
    for (int i = 0; i < 32; i++) {
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

    for (uint8_t yp = 0U; yp <= 1U; yp++) {
        /* Patch v byte (27 or 28) into last two chars of the v field */
        const uint8_t v = 27U + yp;
        hexBuf[vOffset + 62] = hexChars[v >> 4];
        hexBuf[vOffset + 63] = hexChars[v & 0x0f];

        WiFiSSLClient wifiClient;
        HttpClient client(wifiClient, RPC_HOST, RPC_PORT);
        client.beginRequest();
        client.post("/");
        client.sendHeader("Content-Type", "application/json");
        client.sendHeader("Content-Length", bodyLen);
        client.beginBody();
        client.print(kPrefix);
        client.print(hexBuf);
        client.print(kSuffix);
        client.endRequest();

        int status = client.responseStatusCode();
        Serial.print(yp); Serial.print(':'); Serial.println(status);
        if (status != 200) {
            client.stop();
            continue;
        }
        String response = client.responseBody();
        int resultIdx = response.indexOf("\"result\"");
        if (resultIdx < 0) { continue; }
        int hexIdx = response.indexOf("0x", resultIdx);
        if (hexIdx < 0) { continue; }
        /* ecrecover returns 32-byte word; address = last 20 bytes = last 40 hex chars */
        String recovered = response.substring(hexIdx + 26, hexIdx + 66);
        Serial.print(F("got:")); Serial.println(recovered);
        Serial.print(F("exp:")); Serial.println(ADDR_FROM);
        if (recovered.equalsIgnoreCase(ADDR_FROM)) {
            client.stop();
            return yp;
        }
        client.stop();
    }
    return 0xFFU; /* could not determine */
}

/**
 * @brief Fetch the current nonce for ADDR_FROM via eth_getTransactionCount.
 * @return Current nonce (pending), or 0 on failure after retries.
 */
uint64_t fetchNonce() {
    static const char kPfx[] =
        "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"eth_getTransactionCount\","
        "\"params\":[\"0x";
    static const char kSfx[] = "\",\"pending\"]}";
    const int bodyLen = (int)(sizeof(kPfx)-1) + 40 + (int)(sizeof(kSfx)-1);

    for (uint8_t attempt = 0; attempt < 3; attempt++) {
        if (attempt) delay(1000);
        WiFiSSLClient wifiClient;
        HttpClient client(wifiClient, RPC_HOST, RPC_PORT);
        client.beginRequest();
        client.post("/");
        client.sendHeader("Content-Type", "application/json");
        client.sendHeader("Content-Length", bodyLen);
        client.beginBody();
        client.print(kPfx);
        client.print(ADDR_FROM);
        client.print(kSfx);
        client.endRequest();

        int status = client.responseStatusCode();
        Serial.print(F("Nonce status:")); Serial.println(status);
        if (status != 200) { client.stop(); continue; }
        String resp = client.responseBody();
        client.stop();
        int ri = resp.indexOf("\"result\"");
        if (ri < 0) continue;
        int xi = resp.indexOf("0x", ri);
        if (xi < 0) continue;
        uint64_t nonce = 0;
        for (int i = xi + 2; i < (int)resp.length(); i++) {
            char c = resp[i];
            if (!((c>='0'&&c<='9')||(c>='a'&&c<='f')||(c>='A'&&c<='F'))) break;
            nonce = (nonce << 4) | fromHex(c);
        }
        Serial.print(F("Nonce:")); Serial.println((uint32_t)nonce);
        return nonce;
    }
    Serial.println(F("fetchNonce failed!"));
    return 0;
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
    Serial.print("Connecting to WiFi...");
    WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
    while (WiFi.status() != WL_CONNECTED) {
        delay(500); Serial.print(".");
    }
    Serial.println("OK");
    delay(2000); /* Allow network stack to stabilise before first SSL connection */

    /* Build ERC-20 calldata */
    uint8_t calldata[68];
    size_t calLen = encodeERC20Transfer(calldata);

    /* Build unsigned EIP-1559 transaction */
    Tx2 tx2;
    tx2.nonce              = fetchNonce();
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
        if (attempt) delay(1000);
        CW_SecureSession session;
        while (!wallet.connect(session)) { delay(200); }
        Serial.println(F("Card connected, secure channel established."));

        CW_SignRequest signReq(session, CW_SIGN_CURR_K1, CW_SIGN_SIG_ECDSA_LOW_S, CW_SIGN_WITH_PIN);
        signReq.hash       = hashKeccak;
        signReq.hashLength = CW_HASH_SIZE;
        memcpy(signReq.pin, CARD_PIN, CARD_PIN_LEN);

    // ---- PRINT DERIVATION PATH ----
    Serial.print(F("derivePathLength = "));
    Serial.println(signReq.derivePathLength);

    Serial.print(F("derivePath = "));
    for (uint8_t i = 0; i < signReq.derivePathLength / sizeof(uint32_t); i++) {
        Serial.print("0x");
        Serial.print(signReq.derivePath[i], HEX);
        Serial.print(" ");
    }
    Serial.println();

    // ---- PRINT PIN ----
    Serial.print(F("PIN = "));
    for (uint8_t i = 0; i < CARD_PIN_LEN; i++) {
        Serial.print(signReq.pin[i], HEX);
        Serial.print(" ");
    }
    Serial.println();

        signResult = wallet.sign(signReq);
        wallet.disconnect(session);
        if (signResult.errorCode == CW_OK) break;
        Serial.print(F("Sign attempt ")); Serial.print(attempt + 1U); Serial.println(F(" failed."));
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
    if (yParity == 0xFFU) {
        Serial.println(F("yParity determination failed! Halting."));
        while(1);
    }
    Serial.print("yParity: "); Serial.println(yParity);

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
