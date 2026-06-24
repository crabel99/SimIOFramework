#pragma once

#include <stdint.h>

enum EthernetFrameLinkStatus {
  EthernetFrameLinkOff = 0,
  EthernetFrameLinkOn = 1,
  EthernetFrameLinkUnknown = 2,
};

enum EthernetFrameLinkSpeed {
  EthernetFrameSpeedUnknown = 0,
  EthernetFrameSpeed10M = 10,
  EthernetFrameSpeed100M = 100,
};

enum EthernetFrameDuplex {
  EthernetFrameDuplexUnknown = 0,
  EthernetFrameHalfDuplex = 1,
  EthernetFrameFullDuplex = 2,
};

class EthernetFrameDriver {
public:
  using FrameReceiveCallback = void (*)(const uint8_t *frame, uint16_t length,
                                        void *context);
  using LinkChangeCallback = void (*)(EthernetFrameLinkStatus status,
                                      EthernetFrameLinkSpeed speed,
                                      EthernetFrameDuplex duplex,
                                      void *context);
  using CarrierCallback = void (*)(bool carrierUp, void *context);

  virtual ~EthernetFrameDriver() = default;

  virtual EthernetFrameLinkStatus linkStatus() const = 0;
  virtual EthernetFrameLinkSpeed linkSpeed() const = 0;
  virtual EthernetFrameDuplex duplex() const = 0;
  virtual bool carrierUp() const = 0;
  virtual void setFrameReceiveCallback(FrameReceiveCallback callback,
                                       void *context = nullptr) = 0;
  virtual void clearFrameReceiveCallback() = 0;
  virtual void setLinkChangeCallback(LinkChangeCallback callback,
                                     void *context = nullptr) = 0;
  virtual void clearLinkChangeCallback() = 0;
  virtual void setCarrierCallback(CarrierCallback callback,
                                  void *context = nullptr) = 0;
  virtual void clearCarrierCallback() = 0;
  virtual bool frameAvailable(uint16_t *length = nullptr) = 0;
  virtual bool readFrame(uint8_t *buffer, uint16_t capacity,
                         uint16_t *length) = 0;
  virtual bool writeFrame(const uint8_t *buffer, uint16_t length) = 0;
  virtual bool service() = 0;
};
