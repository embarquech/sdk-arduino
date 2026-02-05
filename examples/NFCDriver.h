#ifndef NFCDRIVER_H
#define NFCDRIVER_H
#include <Arduino.h>

class NFCDriver {
public:
    virtual bool begin() = 0;
    virtual bool inListPassiveTarget() = 0;
    virtual bool sendAPDU(const uint8_t* apdu, uint16_t apduLen,
                          uint8_t* response, uint8_t& responseLen) = 0;
    virtual void resetReader() = 0;
    virtual bool printFirmwareVersion() = 0;

    virtual ~NFCDriver() {}
};

#endif // NFCDRIVER_H