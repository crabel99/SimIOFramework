#pragma once

#include <utility/netif/Netif.h>

enum EthernetLwipErr {
  EthernetLwipErrOk = 0,
  EthernetLwipErrMem,
  EthernetLwipErrVal,
  EthernetLwipErrUse,
  EthernetLwipErrWouldBlock,
};

class EthernetLwipPort {
public:
  using InputCallback = EthernetLwipErr (*)(EthernetPacket *packet,
                                            void *context);
  using LinkChangeCallback = void (*)(bool carrierUp,
                                      EthernetFrameLinkStatus status,
                                      EthernetFrameLinkSpeed speed,
                                      EthernetFrameDuplex duplex,
                                      void *context);

  explicit EthernetLwipPort(EthernetNetif &netif);

  bool begin(EthernetPacketAllocator &allocator);
  void end();
  bool service();

  void setInputCallback(InputCallback callback, void *context = nullptr);
  void clearInputCallback();
  void setLinkChangeCallback(LinkChangeCallback callback,
                             void *context = nullptr);
  void clearLinkChangeCallback();

  EthernetLwipErr output(const uint8_t *frame, uint16_t length);
  bool carrierUp() const;

  static EthernetLwipErr mapOutputResult(EthernetNetifOutputResult result);

private:
  EthernetNetif *_netif;
  InputCallback _inputCallback = nullptr;
  void *_inputContext = nullptr;
  LinkChangeCallback _linkChangeCallback = nullptr;
  void *_linkChangeContext = nullptr;

  bool handleInput(EthernetPacket *packet);
  void handleLinkChange(bool carrierUp, EthernetFrameLinkStatus status,
                        EthernetFrameLinkSpeed speed,
                        EthernetFrameDuplex duplex);
  static bool inputThunk(EthernetPacket *packet, void *context);
  static void linkThunk(bool carrierUp, EthernetFrameLinkStatus status,
                        EthernetFrameLinkSpeed speed,
                        EthernetFrameDuplex duplex, void *context);
};
