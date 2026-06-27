/**
 * @file EthernetClient.h
 * @brief Arduino Client facade backed by a TransportProvider socket.
 *
 * `EthernetClient` owns Arduino `Client` behavior and provider-acquired socket
 * lifetime. It must not allocate lwIP protocol-control blocks directly, manage
 * DNS/TLS policy, inspect Ethernet frames, or touch GMAC/PHY/MIIM hardware.
 */
#pragma once

#include <Client.h>
#include <utility/transport/TransportProvider.h>

class EthernetClient : public Client {
public:
  EthernetClient();
  explicit EthernetClient(EthernetSocket &socket);
  explicit EthernetClient(TransportProvider &provider);
  EthernetClient(TransportProvider &provider, EthernetSocket &socket);
  EthernetClient(const EthernetClient &) = delete;
  EthernetClient &operator=(const EthernetClient &) = delete;
  EthernetClient(EthernetClient &&other);
  EthernetClient &operator=(EthernetClient &&other);
  ~EthernetClient();

  void setSocket(EthernetSocket &socket);
  void setTransportProvider(TransportProvider &provider);
  void clearSocket();

  /**
   * @brief Connect using an attached or provider-acquired socket.
   *
   * The call fails closed when no socket/provider exists, carrier is down, or
   * the provider cannot connect. Provider-acquired sockets are released on
   * failed connect attempts. `stop()`, destruction, and move assignment release
   * provider-owned sockets exactly once.
   */
  int connect(IPAddress ip, uint16_t port) override;
  int connect(const char *host, uint16_t port) override;

  /**
   * @brief Delegate stream operations only while the socket reports connected.
   */
  size_t write(uint8_t value) override;
  size_t write(const uint8_t *buffer, size_t size) override;
  int available() override;
  int read() override;
  int read(uint8_t *buffer, size_t size) override;
  int peek() override;
  void flush() override;

  /**
   * @brief Stop the socket and release provider-owned handles.
   */
  void stop() override;
  uint8_t connected() override;
  operator bool() override;

  using Print::write;

protected:
  virtual EthernetSocket *acquireProviderSocket();
  TransportProvider *transportProvider() const { return _provider; }

private:
  bool ensureSocket();
  void releaseOwnedSocket();

  EthernetSocket *_socket;
  TransportProvider *_provider;
  bool _ownsSocket;
};
