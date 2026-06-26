#pragma once

#include <utility/netif/Netif.h>
#include <utility/transport/TransportProvider.h>

enum EthernetLwipErr {
  EthernetLwipErrOk = 0,
  EthernetLwipErrMem,
  EthernetLwipErrVal,
  EthernetLwipErrUse,
  EthernetLwipErrWouldBlock,
};

class EthernetLwipPort : public TransportProvider {
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

  EthernetSocket *acquireClientSocket() override;
  EthernetSocket *acquireSecureClientSocket() override;
  void releaseSocket(EthernetSocket *socket) override;
  bool tlsAvailable() const override;

  bool beginServer(uint16_t port) override;
  void stopServer(uint16_t port) override;
  EthernetSocket *acceptClientSocket(uint16_t port) override;
  size_t writeServer(uint16_t port, uint8_t value) override;
  size_t writeServer(uint16_t port, const uint8_t *buffer,
                     size_t size) override;

  uint8_t beginUdp(uint16_t port) override;
  uint8_t beginUdpMulticast(IPAddress ip, uint16_t port) override;
  void stopUdp() override;
  int beginUdpPacket(IPAddress ip, uint16_t port) override;
  int beginUdpPacket(const char *host, uint16_t port) override;
  int endUdpPacket() override;
  size_t writeUdp(uint8_t value) override;
  size_t writeUdp(const uint8_t *buffer, size_t size) override;
  int parseUdpPacket() override;
  int availableUdp() override;
  int readUdp() override;
  int readUdp(uint8_t *buffer, size_t size) override;
  int peekUdp() override;
  void flushUdp() override;
  IPAddress remoteUdpIP() override;
  uint16_t remoteUdpPort() override;

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
