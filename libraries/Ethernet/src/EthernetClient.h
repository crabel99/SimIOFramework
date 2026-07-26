/**
 * @file EthernetClient.h
 * @brief Arduino Client facade backed by a TransportProvider socket.
 *
 * `EthernetClient` owns Arduino `Client` behavior and provider-acquired socket
 * lifetime. It must not allocate lwIP protocol-control blocks directly, manage
 * DNS/TLS policy, inspect Ethernet frames, or touch GMAC/PHY/MIIM hardware.
 */
#pragma once

#include <utility/EthernetTarget.h>

#include <Client.h>
#include <utility/transport/TransportProvider.h>

class EthernetClient : public Client {
public:
  /**
   * @brief Construct using the registered default provider, if any.
   *
   * The provider is snapshotted at construction. If no default provider is
   * registered, the client remains fail-closed until a socket or provider is
   * explicitly supplied.
   */
  EthernetClient();

  /**
   * @brief Construct around an explicit socket supplied by the caller.
   */
  explicit EthernetClient(EthernetSocket &socket);

  /**
   * @brief Construct around an explicit transport provider.
   */
  explicit EthernetClient(TransportProvider &provider);

  /**
   * @brief Construct around an accepted provider-owned socket.
   */
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
   * failed connect attempts. A nonzero return means the provider accepted or
   * completed the connect request; non-blocking providers may still be
   * resolving DNS or completing TCP setup, so callers observe completion
   * through `connected()` and stream readiness. Hostname DNS state and
   * transport retry/timeout policy remain provider-owned and are not surfaced
   * as separate `EthernetClient` states. `stop()`, destruction, and move
   * assignment release provider-owned sockets exactly once.
   */
  int connect(IPAddress ip, uint16_t port) override;
  int connect(const char *host, uint16_t port) override;

  /**
   * @brief Delegate stream operations through the attached socket.
   *
   * Writes fail closed unless the socket reports connected. Reads, peek, and
   * available still delegate after remote close so bytes already accepted by
   * the backend can be drained before the public client is stopped/released.
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
  EthernetSocket *currentSocket() const { return _socket; }

private:
  bool ensureSocket();
  void releaseOwnedSocket();

  EthernetSocket *_socket;
  TransportProvider *_provider;
  bool _ownsSocket;
};
