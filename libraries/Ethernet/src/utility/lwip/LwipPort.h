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

#include <utility/lwip/LwipTcpSocket.h>
#include <utility/netif/Netif.h>
#include <utility/transport/TransportProvider.h>

#if defined(__has_include)
#if __has_include(<lwip/netif.h>)
#define SIMIO_ETHERNET_HAS_LWIP_CORE 1
#include <lwip/netif.h>
#endif
#endif

#ifndef SIMIO_ETHERNET_HAS_LWIP_CORE
#define SIMIO_ETHERNET_HAS_LWIP_CORE 0
#endif

enum EthernetLwipErr {
  EthernetLwipErrOk = 0,
  EthernetLwipErrMem,
  EthernetLwipErrVal,
  EthernetLwipErrUse,
  EthernetLwipErrWouldBlock,
};

class LwipUdpBackend {
public:
  virtual ~LwipUdpBackend() = default;

  virtual uint8_t begin(uint16_t port) = 0;
  virtual uint8_t beginMulticast(IPAddress ip, uint16_t port) = 0;
  virtual void stop() = 0;
  virtual int beginPacket(IPAddress ip, uint16_t port) = 0;
  virtual int beginPacket(const char *host, uint16_t port) = 0;
  virtual int endPacket() = 0;
  virtual size_t write(uint8_t value) = 0;
  virtual size_t write(const uint8_t *buffer, size_t size) = 0;
  virtual int parsePacket() = 0;
  virtual int available() = 0;
  virtual int read() = 0;
  virtual int read(uint8_t *buffer, size_t size) = 0;
  virtual int peek() = 0;
  virtual void flush() = 0;
  virtual IPAddress remoteIP() = 0;
  virtual uint16_t remotePort() = 0;
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
  ~EthernetLwipPort();

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
  void setTcpBackend(LwipTcpSocketBackend &backend);
  void clearTcpBackend();
  void setUdpBackend(LwipUdpBackend &backend);
  void clearUdpBackend();

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
  LwipTcpSocketBackend *_tcpBackend = nullptr;
  LwipTcpSocket _clientSocket;
  LwipTcpSocket _secureClientSocket;
  LwipTcpSocket _acceptedSocket;
  LwipUdpBackend *_udpBackend = nullptr;
#if SIMIO_ETHERNET_HAS_LWIP_CORE
  struct netif _lwipNetif;
  bool _lwipInitialized = false;
  bool _lwipNetifAdded = false;
  uint8_t _outputBuffer[1536];
#endif

  bool handleInput(EthernetPacket *packet);
  void handleLinkChange(bool carrierUp, EthernetFrameLinkStatus status,
                        EthernetFrameLinkSpeed speed,
                        EthernetFrameDuplex duplex);
#if SIMIO_ETHERNET_HAS_LWIP_CORE
  bool beginLwipNetif();
  void endLwipNetif();
  bool inputPacketToLwip(EthernetPacket *packet);
  EthernetLwipErr outputPbuf(struct pbuf *p);
  static err_t lwipNetifInit(struct netif *netif);
  static err_t lwipLinkOutput(struct netif *netif, struct pbuf *p);
#endif
  static bool inputThunk(EthernetPacket *packet, void *context);
  static void linkThunk(bool carrierUp, EthernetFrameLinkStatus status,
                        EthernetFrameLinkSpeed speed,
                        EthernetFrameDuplex duplex, void *context);
};
