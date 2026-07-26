/**
 * @file Netif.h
 * @brief Hardware-independent Ethernet network-interface contract.
 *
 * `EthernetNetif` sits above `EthernetFrameDriver` and below the future lwIP
 * binding. It owns packet allocation/copying for inbound frames, maps outbound
 * frame attempts to explicit fail-fast result codes, and turns hardware
 * carrier/link changes into stack-facing notifications.
 *
 * This layer must not know SAME5x registers, GMAC descriptors, PHY registers,
 * MDIO/MIIM operations, IP addressing policy, TCP/UDP/TLS sockets, or lwIP
 * object internals.
 */
#pragma once

#include <utility/netif/FrameDriver.h>

#include <stdint.h>

class EthernetPacket {
public:
  virtual ~EthernetPacket() = default;

  /**
   * @brief Return immutable packet bytes owned by the packet object.
   */
  virtual const uint8_t *data() const = 0;
  virtual uint16_t length() const = 0;

  /**
   * @brief Release a packet rejected by the stack input callback.
   *
   * If the stack accepts the packet, ownership transfers to that stack callback
   * and `EthernetNetif` does not release it.
   */
  virtual void release() = 0;
};

class EthernetPacketAllocator {
public:
  virtual ~EthernetPacketAllocator() = default;

  /**
   * @brief Allocate a packet and copy one complete Ethernet frame into it.
   */
  virtual EthernetPacket *allocateCopy(const uint8_t *frame,
                                       uint16_t length) = 0;
};

/**
 * @brief Result of one non-blocking outbound Ethernet frame attempt.
 */
enum EthernetNetifOutputResult {
  EthernetNetifOutputSent = 0,
  EthernetNetifOutputNotStarted,
  EthernetNetifOutputCarrierDown,
  EthernetNetifOutputInvalidFrame,
  EthernetNetifOutputDriverBusy,
};

class EthernetNetif {
public:
  /**
   * @brief Stack input callback.
   *
   * Return true to accept ownership of `packet`. Return false to reject it; the
   * netif releases the packet before returning to the frame driver callback.
   */
  using InputCallback = bool (*)(EthernetPacket *packet, void *context);

  /**
   * @brief Stack-facing carrier/link notification callback.
   */
  using LinkChangeCallback = void (*)(bool carrierUp,
                                      EthernetFrameLinkStatus status,
                                      EthernetFrameLinkSpeed speed,
                                      EthernetFrameDuplex duplex,
                                      void *context);

  explicit EthernetNetif(EthernetFrameDriver &driver);

  /**
   * @brief Attach driver callbacks and cache initial carrier/link state.
   */
  bool begin();

  /**
   * @brief Detach driver callbacks and stop accepting service/output work.
   */
  void end();

  /**
   * @brief Advance bounded driver work.
   */
  bool service();

  void setPacketAllocator(EthernetPacketAllocator &allocator);
  void clearPacketAllocator();
  void setInputCallback(InputCallback callback, void *context = nullptr);
  void clearInputCallback();
  void setLinkChangeCallback(LinkChangeCallback callback,
                             void *context = nullptr);
  void clearLinkChangeCallback();

  bool carrierUp() const { return _carrierUp; }
  EthernetFrameLinkStatus linkStatus() const { return _linkStatus; }
  EthernetFrameLinkSpeed linkSpeed() const { return _linkSpeed; }
  EthernetFrameDuplex duplex() const { return _duplex; }

  /**
   * @brief Attempt to transmit one complete Ethernet frame.
   *
   * This call is fail-fast: it validates started/carrier/input state and calls
   * the frame driver once. It does not poll for carrier, TX descriptor space, or
   * later driver progress.
   */
  EthernetNetifOutputResult outputResult(const uint8_t *frame,
                                         uint16_t length);
  bool output(const uint8_t *frame, uint16_t length);

private:
  EthernetFrameDriver *_driver;
  EthernetPacketAllocator *_packetAllocator = nullptr;
  InputCallback _inputCallback = nullptr;
  void *_inputContext = nullptr;
  LinkChangeCallback _linkChangeCallback = nullptr;
  void *_linkChangeContext = nullptr;
  bool _started = false;
  bool _carrierUp = false;
  EthernetFrameLinkStatus _linkStatus = EthernetFrameLinkUnknown;
  EthernetFrameLinkSpeed _linkSpeed = EthernetFrameSpeedUnknown;
  EthernetFrameDuplex _duplex = EthernetFrameDuplexUnknown;

  void refreshLinkState();
  void notifyLinkChange();
  void handleFrame(const uint8_t *frame, uint16_t length);
  void handleLinkChange(EthernetFrameLinkStatus status,
                        EthernetFrameLinkSpeed speed,
                        EthernetFrameDuplex duplex);
  void handleCarrierChange(bool carrierUp);

  static void frameThunk(const uint8_t *frame, uint16_t length,
                         void *context);
  static void linkThunk(EthernetFrameLinkStatus status,
                        EthernetFrameLinkSpeed speed,
                        EthernetFrameDuplex duplex, void *context);
  static void carrierThunk(bool carrierUp, void *context);
};
