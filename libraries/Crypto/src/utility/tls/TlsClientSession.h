/**
 * @file TlsClientSession.h
 * @brief Async TLS client session contract for secure transports.
 *
 * `TlsClientSession` is the boundary between transport-specific secure clients
 * and the Mbed TLS implementation. It owns TLS session state, hostname/trust
 * policy, non-blocking transport binding, and callback-driven operation
 * progress. It must not block inside handshake, read, write, close-notify,
 * entropy, or crypto paths.
 */
#pragma once

#include <utility/tls/TlsTransport.h>

#ifndef MBEDTLS_CONFIG_FILE
#define MBEDTLS_CONFIG_FILE "utility/mbedtls/TlsConfig.h"
#endif

#include <mbedtls/pk.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>

#include <stddef.h>
#include <stdint.h>

namespace Crypto {

using TlsCryptoReadyCallback = void (*)(bool success, void *context);
using TlsEcdhP256Callback = void (*)(bool success, void *context);

/**
 * @brief Async crypto readiness provider for TLS sessions.
 *
 * Implementations own the Mbed TLS RNG/crypto setup required before handshake
 * progress can run. They must return immediately from `beginHandshakeCrypto()`
 * and later report completion through the callback. The callback only marks
 * readiness; TLS protocol progress still happens from `TlsClientSession::poll()`.
 * Once ready, `generateRandom()` must return immediately from already-prepared
 * DRBG state. It must never start entropy collection or block waiting for
 * hardware.
 */
class TlsCryptoProvider {
public:
  virtual ~TlsCryptoProvider() = default;

  virtual bool beginHandshakeCrypto(TlsCryptoReadyCallback callback,
                                    void *context) = 0;
  virtual void reset() = 0;
  virtual bool ready() const = 0;
  virtual bool generateRandom(uint8_t *buffer, size_t length) = 0;
  /**
   * @brief Start async P-256 ECDH shared-secret computation.
   *
   * `privateScalar` is the local 32-byte big-endian scalar. `peerPublicKey`
   * must be the TLS uncompressed form: 0x04 || X || Y. `sharedSecret` receives
   * the 32-byte big-endian X coordinate only after the callback reports
   * success. The default implementation fails closed for test providers and
   * platforms without a hardware ECDH backend.
   */
  virtual bool ecdhP256SharedSecretAsync(const uint8_t privateScalar[32],
                                         const uint8_t peerPublicKey[65],
                                         uint8_t sharedSecret[32],
                                         TlsEcdhP256Callback callback,
                                         void *context) {
    (void)privateScalar;
    (void)peerPublicKey;
    (void)sharedSecret;
    (void)callback;
    (void)context;
    return false;
  }
};

enum class TlsAsyncStatus : uint8_t {
  Idle,
  Busy,
  WantRead,
  WantWrite,
  WaitingCrypto,
  Complete,
  Error,
};

enum class TlsOperation : uint8_t {
  None,
  Handshake,
  Read,
  Write,
  CloseNotify,
};

enum class TlsVerificationPolicy : uint8_t {
  Required,
};

enum class TlsProtocolVersion : uint8_t {
  Tls12,
};

enum class TlsCipherSuite : uint8_t {
  EcdheEcdsaWithAes128GcmSha256,
};

/**
 * @brief Strict TLS policy supported by the current SecureClient profile.
 *
 * The policy is intentionally narrow and fail-closed. Runtime configuration
 * exists so callers and tests can state the contract explicitly; unsupported
 * values are rejected rather than silently widening the protocol surface.
 */
struct TlsClientPolicy {
  TlsVerificationPolicy verification = TlsVerificationPolicy::Required;
  TlsProtocolVersion minVersion = TlsProtocolVersion::Tls12;
  TlsProtocolVersion maxVersion = TlsProtocolVersion::Tls12;
  TlsCipherSuite cipherSuite = TlsCipherSuite::EcdheEcdsaWithAes128GcmSha256;
};

constexpr uint16_t DefaultTlsOperationPollLimit = 20000;
#ifndef SIMIO_TLS_ECC_OPERATION_BUDGET
#define SIMIO_TLS_ECC_OPERATION_BUDGET 32
#endif
constexpr uint32_t DefaultTlsEccOperationBudget =
    SIMIO_TLS_ECC_OPERATION_BUDGET;

class TlsClientSession {
public:
  using Callback = void (*)(TlsAsyncStatus status, void *context);

  TlsClientSession();
  ~TlsClientSession();

  /**
   * @brief Store trust-anchor material lifetime supplied by the caller.
   *
   * Certificate parsing belongs to Mbed TLS and runs through PSA key import.
   * The caller must keep the memory valid for the session lifetime because the
   * session records the original trust material boundary as well as the parsed
   * Mbed TLS chain. This call must fail closed while an operation is active.
   */
  bool configureTrustAnchors(const uint8_t *data, size_t length);

  /**
   * @brief Set the hostname used for SNI and certificate verification.
   */
  bool setHostname(const char *hostname);

  /**
   * @brief Configure the optional client certificate and private key.
   *
   * The caller must keep both buffers valid for the session lifetime. Parsing
   * is delegated to Mbed TLS at configuration time so malformed identity
   * material fails before any handshake begins. This call fails closed while an
   * operation is active and clears any previously configured client identity on
   * parse failure.
   */
  bool configureClientIdentity(const uint8_t *certificate,
                               size_t certificateLength,
                               const uint8_t *privateKey,
                               size_t privateKeyLength);

  /**
   * @brief Configure optional ALPN protocols for future handshakes.
   *
   * `protocols` may be `nullptr` to disable ALPN. Otherwise it must point to a
   * null-terminated list of non-empty protocol strings that remains valid for
   * the session lifetime. The list is bounded by this wrapper before Mbed TLS
   * sees it so missing terminators and oversized names fail closed.
   */
  bool configureAlpnProtocols(const char *const *protocols);
  const char *negotiatedAlpnProtocol() const;

  /**
   * @brief Configure the strict TLS policy used for future handshakes.
   *
   * This call fails while an operation is active. The current implementation
   * supports only TLS 1.2 with required certificate verification and
   * ECDHE-ECDSA-AES128-GCM-SHA256. Unsupported enum values fail closed so
   * adding broader policy later requires explicit implementation and tests.
   */
  bool configurePolicy(const TlsClientPolicy &policy);
  const TlsClientPolicy &policy() const { return _policy; }

  /**
   * @brief Configure the bounded progress deadline for each TLS operation.
   *
   * Each active handshake/read/write/close-notify operation may consume at most
   * `pollLimit` calls to `poll()`. The limit must be nonzero and can only be
   * changed while idle. Expired operations, including a handshake stalled while
   * waiting for async crypto readiness, fail closed and invoke the pending
   * operation callback with `TlsAsyncStatus::Error`.
   */
  bool configureOperationPollLimit(uint16_t pollLimit);
  uint16_t operationPollLimit() const { return _operationPollLimit; }

  /**
   * @brief Enable or disable the in-memory TLS session reuse cache.
   *
   * When enabled, a completed handshake captures Mbed TLS session state for a
   * future handshake on the same `TlsClientSession` instance. The cached session
   * never leaves this object and can only be changed while no TLS operation is
   * active. Disabling reuse clears any cached session material.
   */
  bool enableSessionReuse(bool enabled);
  bool sessionReuseEnabled() const { return _sessionReuseEnabled; }
  bool sessionCached() const { return _sessionCached; }

  /**
   * @brief Clear any cached TLS session material.
   *
   * This is an idle-only operation because Mbed TLS owns session state while a
   * handshake/read/write/close-notify operation is active.
   */
  bool clearSessionCache();

  /**
   * @brief Bind the TLS BIO to an already-created non-blocking transport.
   */
  bool bindTransport(TlsTransport &transport);

  /**
   * @brief Bind the async crypto provider used before TLS handshake progress.
   *
   * A production provider owns the Mbed TLS DRBG/session crypto setup. Tests may
   * inject a mock provider to verify state-machine behavior without hardware.
   */
  bool bindCryptoProvider(TlsCryptoProvider &provider);

  /**
   * @brief Start async TLS handshake progress.
   *
   * The call validates configuration and stores callback state only. `poll()`
   * reports `WaitingCrypto` until the bound `TlsCryptoProvider` has completed
   * async seed/DRBG readiness, then advances one bounded Mbed TLS handshake
   * step per call and reports `WantRead`/`WantWrite` when the transport cannot
   * progress.
   */
  TlsAsyncStatus handshakeAsync(Callback callback, void *context = nullptr);

  /**
   * @brief Start an async TLS read operation.
   */
  TlsAsyncStatus readAsync(uint8_t *buffer, size_t length, Callback callback,
                           void *context = nullptr);

  /**
   * @brief Start an async TLS write operation.
   */
  TlsAsyncStatus writeAsync(const uint8_t *buffer, size_t length,
                            Callback callback, void *context = nullptr);

  /**
   * @brief Start an async TLS close-notify operation.
   */
  TlsAsyncStatus closeNotifyAsync(Callback callback, void *context = nullptr);

  /**
   * @brief Advance one bounded unit of TLS work.
   *
   * ECC-heavy handshake phases are bounded with Mbed TLS/PSA interruptable
   * crypto. When certificate verification, ECDSA verification/signing, or
   * restartable PSA ECC reaches `DefaultTlsEccOperationBudget`, `poll()`
   * returns `TlsAsyncStatus::Busy` with `lastMbedTlsResult()` set to
   * `MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS`. Callers must run the surrounding
   * network/peripheral service loop and call `poll()` again to resume the same
   * Mbed TLS operation. This is the TLS-level contract that prevents
   * ECDHE/ECDSA work from monopolizing the cooperative runtime. Boards may
   * raise `SIMIO_TLS_ECC_OPERATION_BUDGET` to trade longer bounded poll slices
   * for fewer resumes while keeping TLS progress cooperative.
   *
   * This budget is a temporary containment mechanism for Mbed TLS/PSA software
   * ECC during bring-up. Final SAME5x builds must route exact ECDH/ECDSA
   * mappings through async PUKCC adapters instead of relying on software ECC
   * resumes for normal secure-client operation.
   */
  TlsAsyncStatus poll();

  /**
   * @brief Abort session state without attempting close-notify.
   */
  void abort();

  TlsAsyncStatus status() const { return _status; }
  TlsOperation operation() const { return _operation; }
  int lastError() const { return _lastError; }
  int lastMbedTlsResult() const { return _lastMbedTlsResult; }
  uint32_t verificationResult() const { return _verificationResult; }
  bool configured() const;
  bool handshakeComplete() const { return _handshakeComplete; }
  /**
   * @brief Return true after a read observes TLS close-notify from the peer.
   */
  bool peerCloseNotified() const { return _peerCloseNotified; }
  size_t bytesTransferred() const { return _bytesTransferred; }
  int handshakeState() const { return _ssl.MBEDTLS_PRIVATE(state); }

private:
  bool operationActive() const;
  bool startOperation(TlsOperation operation, Callback callback, void *context);
  bool startHandshakeCrypto();
  bool prepareMbedTlsSession();
  void resetMbedTlsSession();
  TlsAsyncStatus pollHandshake();
  TlsAsyncStatus pollRead();
  TlsAsyncStatus pollWrite();
  TlsAsyncStatus pollCloseNotify();
  TlsAsyncStatus handleMbedTlsResult(int result);
  TlsAsyncStatus finish(TlsAsyncStatus status);
  TlsAsyncStatus fail(int error);
  TlsAsyncStatus reject(int error);
  static void handleCryptoReady(bool success, void *context);
  static int bioSend(void *context, const unsigned char *buffer, size_t length);
  static int bioRecv(void *context, unsigned char *buffer, size_t length);

  TlsTransport *_transport;
  TlsCryptoProvider *_cryptoProvider;
  const uint8_t *_trustAnchors;
  size_t _trustAnchorLength;
  const char *_hostname;
  const char *const *_alpnProtocols;
  TlsClientPolicy _policy;
  mbedtls_ssl_context _ssl;
  mbedtls_ssl_config _sslConfig;
  mbedtls_x509_crt _caChain;
  mbedtls_x509_crt _clientCertificate;
  mbedtls_pk_context _clientKey;
  mbedtls_ssl_session _savedSession;
  TlsAsyncStatus _status;
  TlsOperation _operation;
  Callback _callback;
  void *_callbackContext;
  uint8_t *_readBuffer;
  const uint8_t *_writeBuffer;
  size_t _requestedLength;
  size_t _bytesTransferred;
  uint16_t _operationPollLimit;
  uint16_t _operationPollCount;
  int _lastError;
  int _lastMbedTlsResult;
  uint32_t _verificationResult;
  bool _handshakeComplete;
  bool _cryptoReady;
  bool _cryptoFailed;
  bool _tlsConfigured;
  bool _peerCloseNotified;
  bool _clientIdentityConfigured;
  bool _sessionReuseEnabled;
  bool _sessionCached;
};

} // namespace Crypto
