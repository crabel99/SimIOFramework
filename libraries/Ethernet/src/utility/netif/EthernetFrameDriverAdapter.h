#pragma once

#include <Ethernet.h>
#include <utility/netif/EthernetFrameDriver.h>

#ifdef ETHERNET_HARDWARE_AVAILABLE

class EthernetClassFrameDriver : public EthernetFrameDriver {
public:
  explicit EthernetClassFrameDriver(EthernetClass &ethernet);

  EthernetFrameLinkStatus linkStatus() const override;
  EthernetFrameLinkSpeed linkSpeed() const override;
  EthernetFrameDuplex duplex() const override;
  bool carrierUp() const override;
  void setFrameReceiveCallback(FrameReceiveCallback callback,
                               void *context = nullptr) override;
  void clearFrameReceiveCallback() override;
  void setLinkChangeCallback(LinkChangeCallback callback,
                             void *context = nullptr) override;
  void clearLinkChangeCallback() override;
  void setCarrierCallback(CarrierCallback callback,
                          void *context = nullptr) override;
  void clearCarrierCallback() override;
  bool frameAvailable(uint16_t *length = nullptr) override;
  bool readFrame(uint8_t *buffer, uint16_t capacity, uint16_t *length) override;
  bool writeFrame(const uint8_t *buffer, uint16_t length) override;
  bool service() override;

private:
  EthernetClass *_ethernet;
  LinkChangeCallback _linkChangeCallback = nullptr;
  void *_linkChangeContext = nullptr;

  static void handleLinkChange(EthernetLinkStatus status,
                               EthernetPhyLinkSpeed speed,
                               EthernetPhyDuplex duplex, void *context);
};
#endif /* ETHERNET_HARDWARE_AVAILABLE */
