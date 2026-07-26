/**
 * @file FrameDriver.h
 * @brief Hardware-independent Ethernet frame driver boundary.
 *
 * `EthernetFrameDriver` is the narrow contract between the hardware-facing
 * `EthernetClass`/GMAC layer and the network-interface layer. Implementations
 * expose raw Ethernet frame movement, cached carrier/link state, and bounded
 * service progression. They must not own IP addressing, TCP/UDP/TLS sockets,
 * packet allocation policy, lwIP objects, or PHY register sequencing.
 */
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

  /**
   * @brief Return cached link state from the hardware/coordinator layer.
   *
   * These accessors must not synchronously probe PHY registers. Runtime PHY
   * updates arrive through interrupt-driven or explicitly serviced link work.
   */
  virtual EthernetFrameLinkStatus linkStatus() const = 0;
  virtual EthernetFrameLinkSpeed linkSpeed() const = 0;
  virtual EthernetFrameDuplex duplex() const = 0;
  virtual bool carrierUp() const = 0;

  /**
   * @brief Register raw frame and carrier/link event callbacks.
   *
   * Callback execution is controlled by the driver implementation. The driver
   * does not transfer ownership of the frame pointer; consumers that need to
   * retain a frame must copy it before returning.
   */
  virtual void setFrameReceiveCallback(FrameReceiveCallback callback,
                                       void *context = nullptr) = 0;
  virtual void clearFrameReceiveCallback() = 0;
  virtual void setLinkChangeCallback(LinkChangeCallback callback,
                                     void *context = nullptr) = 0;
  virtual void clearLinkChangeCallback() = 0;
  virtual void setCarrierCallback(CarrierCallback callback,
                                  void *context = nullptr) = 0;
  virtual void clearCarrierCallback() = 0;

  /**
   * @brief Optional pull-style raw frame access for hardware tests/adapters.
   */
  virtual bool frameAvailable(uint16_t *length = nullptr) = 0;
  virtual bool readFrame(uint8_t *buffer, uint16_t capacity,
                         uint16_t *length) = 0;

  /**
   * @brief Attempt to transmit one complete Ethernet frame.
   *
   * Returns immediately. A false result means the frame was not accepted by the
   * driver; callers must not spin or poll for later TX space inside this call.
   */
  virtual bool writeFrame(const uint8_t *buffer, uint16_t length) = 0;

  /**
   * @brief Advance bounded driver work.
   */
  virtual bool service() = 0;
};
