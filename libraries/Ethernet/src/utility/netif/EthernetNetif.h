#pragma once

#include <utility/netif/EthernetFrameDriver.h>
#include <utility/netif/EthernetPacket.h>

#include <stdint.h>

enum EthernetNetifOutputResult {
  EthernetNetifOutputSent = 0,
  EthernetNetifOutputNotStarted,
  EthernetNetifOutputCarrierDown,
  EthernetNetifOutputInvalidFrame,
  EthernetNetifOutputDriverBusy,
};

class EthernetNetif {
public:
  using InputCallback = bool (*)(EthernetPacket *packet, void *context);
  using LinkChangeCallback = void (*)(bool carrierUp,
                                      EthernetFrameLinkStatus status,
                                      EthernetFrameLinkSpeed speed,
                                      EthernetFrameDuplex duplex,
                                      void *context);

  explicit EthernetNetif(EthernetFrameDriver &driver);

  bool begin();
  void end();
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
