/**
 * @file SecureClient.h
 * @brief TLS-capable EthernetClient facade.
 *
 * `SecureClient` extends `EthernetClient` with TLS policy and async handshake
 * orchestration. Ethernet still owns socket acquisition and carrier state; the
 * Crypto library owns TLS session state, trust anchors, entropy, and protocol
 * progress. `SecureClient` adapts the selected Ethernet socket into the Crypto
 * TLS transport boundary and fails closed until TLS is configured and the
 * handshake has completed.
 */
#pragma once

#include <EthernetClient.h>
#include <utility/tls/TlsClientSession.h>
#include <utility/transport/TransportProvider.h>

enum SecureClientError : int {
  SecureClientNoError = 0,
  SecureClientTlsUnavailable = -1,
  SecureClientConnectFailed = -2,
  SecureClientTlsNotConfigured = -3,
  SecureClientTlsHandshakeStartFailed = -4,
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
   * @brief Configure trust anchors used by the TLS verifier.
   *
   * The caller must keep `data` valid for the secure client lifetime. Parsing is
   * delegated to Mbed TLS through `TlsClientSession`; this method fails closed
   * while a TLS operation is active.
   */
  bool setTrustAnchors(const uint8_t *data, size_t length);

  /**
   * @brief Set the hostname used for TLS SNI and certificate verification.
   *
   * `connect(const char*, uint16_t)` updates this automatically from `host`.
   * IP-based connects require the caller to set a verification hostname first.
   */
  bool setHostname(const char *hostname);

  /**
   * @brief Bind the async TLS crypto provider.
   */
  bool setCryptoProvider(Crypto::TlsCryptoProvider &provider);

  /**
   * @brief Advance one bounded TLS operation step.
   */
  Crypto::TlsAsyncStatus pollTls();

  Crypto::TlsAsyncStatus tlsStatus() const;
  int tlsLastError() const;
  uint32_t tlsVerificationResult() const;
  bool tlsHandshakeComplete() const;

  /**
   * @brief TLS stream operations fail closed until handshake completion.
   */
  size_t write(uint8_t value) override;
  size_t write(const uint8_t *buffer, size_t size) override;
  int available() override;
  int read() override;
  int read(uint8_t *buffer, size_t size) override;
  int peek() override;
  void flush() override;
  void stop() override;
  uint8_t connected() override;

  /**
   * @brief Return whether the attached provider can create secure sockets.
   */
  bool tlsAvailable() const;

  /**
   * @brief Return the last secure-connect error code.
   */
  int lastError() const;

private:
  class SocketTlsTransport : public Crypto::TlsTransport {
  public:
    void bind(EthernetSocket *socket) { _socket = socket; }
    void clear() { _socket = nullptr; }

    bool carrierUp() const override;
    uint8_t connected() override;
    size_t write(const uint8_t *buffer, size_t size) override;
    int available() override;
    int read(uint8_t *buffer, size_t size) override;
    void stop() override;

  private:
    EthernetSocket *_socket = nullptr;
  };

  EthernetSocket *acquireProviderSocket() override;
  bool tlsConfigurationReady() const;
  bool prepareTlsSession();
  bool startTlsHandshake();
  void clearTlsState();
  static void handleTlsCallback(Crypto::TlsAsyncStatus status, void *context);

  int _lastError;
  const uint8_t *_trustAnchors;
  size_t _trustAnchorLength;
  char _hostname[128];
  Crypto::TlsCryptoProvider *_cryptoProvider;
  SocketTlsTransport _tlsTransport;
  Crypto::TlsClientSession _tlsSession;
  Crypto::TlsAsyncStatus _lastTlsCallbackStatus;
};
