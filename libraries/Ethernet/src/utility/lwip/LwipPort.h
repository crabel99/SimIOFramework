/**
 * @file LwipPort.h
 * @brief Boundary between EthernetNetif and the lwIP-facing transport layer.
 *
 * `EthernetLwipPort` is the only layer that should translate netif packet,
 * carrier, and output semantics into lwIP-style behavior. Until real lwIP is
 * imported, it preserves those contracts and fails TCP/UDP/TLS socket
 * operations closed through `TransportProvider`.
 *
 * This layer must not know SAME5x hardware details, GMAC descriptors, PHY
 * registers, or MDIO/MIIM operations. It must also not let public
 * `EthernetClient`, `EthernetServer`, `EthernetUDP`, or `SecureClient` classes
 * own lwIP internals directly.
 */
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
  /**
   * @brief lwIP-style packet input callback.
   *
   * `EthernetLwipErrOk` accepts packet ownership. Any other result rejects the
   * packet and lets `EthernetNetif` release it.
   */
  using InputCallback = EthernetLwipErr (*)(EthernetPacket *packet,
                                            void *context);

  /**
   * @brief Carrier/link notification forwarded from `EthernetNetif`.
   */
  using LinkChangeCallback = void (*)(bool carrierUp,
                                      EthernetFrameLinkStatus status,
                                      EthernetFrameLinkSpeed speed,
                                      EthernetFrameDuplex duplex,
                                      void *context);

  explicit EthernetLwipPort(EthernetNetif &netif);

  /**
   * @brief Wire packet allocation and callbacks into the netif.
   */
  bool begin(EthernetPacketAllocator &allocator);

  /**
   * @brief Unwire netif callbacks and fail closed until `begin()` is called.
   */
  void end();

  /**
   * @brief Advance bounded netif/driver work only while started.
   */
  bool service();

  void setInputCallback(InputCallback callback, void *context = nullptr);
  void clearInputCallback();
  void setLinkChangeCallback(LinkChangeCallback callback,
                             void *context = nullptr);
  void clearLinkChangeCallback();

  /**
   * @brief Send one raw Ethernet frame through the netif and map the result.
   */
  EthernetLwipErr output(const uint8_t *frame, uint16_t length);

  /**
   * @brief Return current carrier state only while the port is started.
   */
  bool carrierUp() const;

  /**
   * @brief Convert netif output results into the lwIP-style error model.
   */
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
  bool _started = false;

  bool handleInput(EthernetPacket *packet);
  void handleLinkChange(bool carrierUp, EthernetFrameLinkStatus status,
                        EthernetFrameLinkSpeed speed,
                        EthernetFrameDuplex duplex);
  static bool inputThunk(EthernetPacket *packet, void *context);
  static void linkThunk(bool carrierUp, EthernetFrameLinkStatus status,
                        EthernetFrameLinkSpeed speed,
                        EthernetFrameDuplex duplex, void *context);
};
