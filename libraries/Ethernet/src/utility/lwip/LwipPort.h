/**
 * @file LwipPort.h
 * @brief Boundary between EthernetNetif and the lwIP-facing transport layer.
 *
 * `EthernetLwipPort` is the only layer that should translate netif packet,
 * carrier, address configuration, and output semantics into lwIP behavior. It
 * owns lwIP netif setup/status and routes public transport-provider calls to
 * lwIP-backed TCP/UDP/TLS adapters.
 *
 * This layer must not know SAME5x hardware details, GMAC descriptors, PHY
 * registers, or MDIO/MIIM operations. It must also not let public
 * `EthernetClient`, `EthernetServer`, `EthernetUDP`, or `SecureClient` classes
 * own lwIP internals directly.
 */
#pragma once

#include <utility/lwip/LwipTcpSocket.h>
#include <utility/netif/Netif.h>
#include <utility/network/NetworkConfig.h>
#include <utility/network/TimeService.h>
#include <utility/transport/TransportProvider.h>

#include <lwip/netif.h>

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

  /**
   * @brief Bind, send, receive, and release one provider-owned UDP endpoint.
   *
   * Implementations own the UDP PCB/socket state. Calls must be bounded and
   * fail closed when the endpoint is not active, the packet is invalid, or DNS
   * cannot complete immediately.
   */
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
   * @brief Internal network state snapshot below the Arduino API.
   *
   * This gives service/test code one compact view of carrier, DHCP, and IPv4
   * assignment state without exposing lwIP internals through EthernetClient,
   * EthernetServer, EthernetUDP, or SecureClient.
   */
  struct NetworkStateSnapshot {
    bool started = false;
    bool carrierUp = false;
    bool dhcpActive = false;
    bool dhcpAddressSupplied = false;
    bool addressAssigned = false;
    IPAddress localIp;
    IPAddress gateway;
    IPAddress subnet;
    IPAddress dnsServer;
  };

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

  /**
   * @brief Internal notification for carrier/DHCP/address state changes.
   */
  using NetworkStateCallback = void (*)(const NetworkStateSnapshot &state,
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
  /**
   * @brief Run due lwIP NO_SYS timeout handlers.
   *
   * This is normally driven by the RTC periodic interrupt selected by
   * NetworkService. It is separate from service() so packet/driver progress
   * does not also own lwIP timer progression.
   */
  void checkTimeouts();

  void setInputCallback(InputCallback callback, void *context = nullptr);
  void clearInputCallback();
  void setLinkChangeCallback(LinkChangeCallback callback,
                             void *context = nullptr);
  void clearLinkChangeCallback();
  void setNetworkStateCallback(NetworkStateCallback callback,
                               void *context = nullptr);
  void clearNetworkStateCallback();

  /**
   * @brief Return the current internal carrier/DHCP/address snapshot.
   */
  NetworkStateSnapshot networkState() const;

  /**
   * @brief Store and, when started, apply DHCP/static lwIP addressing.
   *
   * DHCP application starts lwIP's DHCP client and returns immediately; callers
   * observe lease progress through `dhcpActive()`, `dhcpAddressSupplied()`, and
   * `addressAssigned()`.
   */
  bool configureNetwork(const NetworkConfig &config);

  /**
   * @brief Return true when DHCP mode has attached an active lwIP DHCP client.
   */
  bool dhcpActive() const;

  /**
   * @brief Return true when the active DHCP client has supplied an address.
   */
  bool dhcpAddressSupplied() const;

  /**
   * @brief Return true when lwIP has a non-zero local IPv4 address.
   */
  bool addressAssigned() const;

  /**
   * @brief Return current lwIP IPv4 status values or zero when unavailable.
   */
  IPAddress localIP() const;
  IPAddress gatewayIP() const;
  IPAddress subnetMask() const;
  IPAddress dnsServerIP() const;

  /**
   * @brief Attach concrete TCP and UDP backend implementations.
   *
   * Changing a backend releases owned client/listener/endpoint state so public
   * objects fail closed instead of retaining stale provider handles.
   */
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
  NetworkTimeService *networkTimeService() override;

  /**
   * @brief TCP listener operations delegated to the attached TCP backend.
   */
  bool beginServer(uint16_t port) override;
  void stopServer(uint16_t port) override;
  EthernetSocket *acceptClientSocket(uint16_t port) override;
  size_t writeServer(uint16_t port, uint8_t value) override;
  size_t writeServer(uint16_t port, const uint8_t *buffer,
                     size_t size) override;

  /**
   * @brief UDP endpoint and packet operations delegated to the UDP backend.
   */
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
  NetworkStateCallback _networkStateCallback = nullptr;
  void *_networkStateContext = nullptr;
  NetworkStateSnapshot _lastNetworkState;
  NetworkConfig _networkConfig;
  bool _started = false;
  LwipTcpSocketBackend *_tcpBackend = nullptr;
  LwipTcpSocket _clientSocket;
  LwipTcpSocket _secureClientSocket;
  LwipTcpSocket _acceptedSocket;
  LwipUdpBackend *_udpBackend = nullptr;
  uint8_t _outputBuffer[1536];

  bool handleInput(EthernetPacket *packet);
  void handleLinkChange(bool carrierUp, EthernetFrameLinkStatus status,
                        EthernetFrameLinkSpeed speed,
                        EthernetFrameDuplex duplex);
  bool beginLwipNetif();
  void endLwipNetif();
  bool applyNetworkConfigToLwip();
  bool inputPacketToLwip(EthernetPacket *packet);
  void notifyNetworkStateIfChanged();
  EthernetLwipErr outputPbuf(struct pbuf *p);
  static err_t lwipNetifInit(struct netif *netif);
  static err_t lwipLinkOutput(struct netif *netif, struct pbuf *p);
  static bool inputThunk(EthernetPacket *packet, void *context);
  static void linkThunk(bool carrierUp, EthernetFrameLinkStatus status,
                        EthernetFrameLinkSpeed speed,
                        EthernetFrameDuplex duplex, void *context);
};
