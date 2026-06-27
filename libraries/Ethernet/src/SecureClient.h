/**
 * @file SecureClient.h
 * @brief TLS-capable EthernetClient facade.
 *
 * `SecureClient` extends `EthernetClient` with TLS availability and error
 * policy. The provider owns TLS socket/session implementation; this class
 * chooses secure socket acquisition and fails closed when TLS is unavailable.
 * Until a concrete TLS session backend is wired, the lwIP backend deliberately
 * reports TLS unavailable.
 */
#pragma once

#include <EthernetClient.h>
#include <utility/transport/TransportProvider.h>

enum SecureClientError : int {
  SecureClientNoError = 0,
  SecureClientTlsUnavailable = -1,
  SecureClientConnectFailed = -2,
};

class SecureClient : public EthernetClient {
public:
  SecureClient();
  explicit SecureClient(EthernetSocket &socket);
  explicit SecureClient(TransportProvider &provider);
  SecureClient(const SecureClient &) = delete;
  SecureClient &operator=(const SecureClient &) = delete;
  SecureClient(SecureClient &&other);
  SecureClient &operator=(SecureClient &&other);

  /**
   * @brief Connect through a TLS-capable provider socket.
   *
   * The call fails closed when TLS is unavailable, the provider cannot acquire a
   * secure socket, carrier is down, or connection setup fails. Provider-owned
   * secure sockets are released on failure, `stop()`, destruction, and move
   * assignment through the inherited `EthernetClient` ownership contract.
   */
  int connect(IPAddress ip, uint16_t port) override;
  int connect(const char *host, uint16_t port) override;

  /**
   * @brief Return whether the attached provider can create secure sockets.
   */
  bool tlsAvailable() const;

  /**
   * @brief Return the last secure-connect error code.
   */
  int lastError() const;

private:
  EthernetSocket *acquireProviderSocket() override;

  int _lastError;
};
