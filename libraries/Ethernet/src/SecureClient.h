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
   * assignment through the inherited `EthernetClient` ownership contract. A
   * successful return means the TCP connect was accepted; `pollTls()` starts
   * the TLS handshake after the provider reports the TCP connection is
   * established.
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
   * @brief Configure the optional client certificate and private key.
   *
   * The caller must keep both buffers valid for the secure client lifetime.
   * Parsing and key validation are delegated to the Crypto TLS session. This
   * method fails closed while a TLS operation is active.
   */
  bool setClientIdentity(const uint8_t *certificate, size_t certificateLength,
                         const uint8_t *privateKey, size_t privateKeyLength);

  /**
   * @brief Configure optional ALPN protocol names for future handshakes.
   *
   * `protocols` may be `nullptr` to disable ALPN. Otherwise it must point to a
   * null-terminated list that remains valid for the secure client lifetime.
   */
  bool setAlpnProtocols(const char *const *protocols);
  const char *negotiatedAlpnProtocol() const;

  /**
   * @brief Bind the async TLS crypto provider.
   */
  bool setCryptoProvider(Crypto::TlsCryptoProvider &provider);

  /**
   * @brief Configure the strict TLS policy used for future handshakes.
   *
   * The current supported policy is intentionally narrow and fail-closed:
   * required certificate verification, TLS 1.2 only, and
   * ECDHE-ECDSA-AES128-GCM-SHA256. Unsupported values are rejected by the
   * Crypto TLS session.
   */
  bool setTlsPolicy(const Crypto::TlsClientPolicy &policy);
  const Crypto::TlsClientPolicy &tlsPolicy() const;

  /**
   * @brief Configure the maximum poll steps for each TLS operation.
   *
   * The limit must be nonzero and can only be changed while no TLS operation is
   * active. Expired TLS operations fail closed and release no caller buffers.
   */
  bool setTlsOperationPollLimit(uint16_t pollLimit);
  uint16_t tlsOperationPollLimit() const;

  /**
   * @brief Enable or disable client-owned TLS session reuse.
   *
   * Session material remains inside the Crypto TLS session and is only reused
   * by later handshakes on this secure client. Disabling reuse clears the
   * cached session. All cache-control calls fail while a TLS operation is
   * active.
   */
  bool enableTlsSessionReuse(bool enabled);
  bool tlsSessionReuseEnabled() const;
  bool tlsSessionCached() const;
  bool clearTlsSessionCache();

  /**
   * @brief Advance one bounded TLS operation step.
   */
  Crypto::TlsAsyncStatus pollTls();

  Crypto::TlsAsyncStatus tlsStatus() const;
  int tlsLastError() const;
  int tlsLastMbedTlsResult() const;
  int tlsHandshakeState() const;
  Crypto::TlsOperation tlsOperation() const;
  bool tlsHandshakePending() const;
  uint32_t tlsVerificationResult() const;
  bool tlsHandshakeComplete() const;
  /**
   * @brief Return true once TLS read progress observes peer close-notify.
   */
  bool tlsPeerCloseNotified() const;

  /**
   * @brief Start a bounded TLS close-notify shutdown.
   *
   * This is the graceful TLS shutdown path. It fails closed until the handshake
   * has completed. Call `pollTls()` to continue `WantRead`/`WantWrite`
   * progress. When close-notify completes or errors, the underlying provider
   * socket is released. `stop()` remains the immediate abort path.
   */
  Crypto::TlsAsyncStatus closeNotifyAsync();

  /**
   * @brief TLS stream operations fail closed until handshake completion.
   *
   * Reads are staged through an internal decrypted RX buffer so `available()`
   * and `peek()` can report plaintext without exposing Mbed TLS internals.
   * Writes copy caller data into an internal TLS TX staging buffer before
   * starting Mbed TLS progress, so caller memory is never retained across
   * `WantRead`/`WantWrite`; callers must use `pollTls()` to continue deferred
   * TLS work. `write()` returns the number of bytes accepted into that staging
   * buffer, and a second write returns 0 while the staged TLS write is still
   * pending. `connected()` is TLS-aware: it reports connected only after the
   * handshake is complete and the underlying provider socket remains connected.
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
  static constexpr size_t TlsRxBufferSize = 512;
  static constexpr size_t TlsTxBufferSize = 512;

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
  Crypto::TlsAsyncStatus advanceTlsOperation();
  bool fillTlsRxBuffer();
  size_t consumeTlsRx(uint8_t *buffer, size_t size);
  size_t tlsRxAvailable() const;
  void clearTlsStreamBuffers();
  void clearTlsState();
  static void handleTlsCallback(Crypto::TlsAsyncStatus status, void *context);

  int _lastError;
  const uint8_t *_trustAnchors;
  size_t _trustAnchorLength;
  const uint8_t *_clientCertificate;
  size_t _clientCertificateLength;
  const uint8_t *_clientPrivateKey;
  size_t _clientPrivateKeyLength;
  const char *const *_alpnProtocols;
  uint16_t _tlsOperationPollLimit;
  bool _tlsSessionReuseEnabled;
  bool _tlsHandshakePending;
  char _hostname[128];
  Crypto::TlsCryptoProvider *_cryptoProvider;
  SocketTlsTransport _tlsTransport;
  Crypto::TlsClientSession _tlsSession;
  Crypto::TlsAsyncStatus _lastTlsCallbackStatus;
  uint8_t _tlsRxBuffer[TlsRxBufferSize] = {};
  size_t _tlsRxLength = 0;
  size_t _tlsRxIndex = 0;
  bool _tlsRxPending = false;
  uint8_t _tlsTxBuffer[TlsTxBufferSize] = {};
  size_t _tlsTxLength = 0;
  bool _tlsTxPending = false;
};
