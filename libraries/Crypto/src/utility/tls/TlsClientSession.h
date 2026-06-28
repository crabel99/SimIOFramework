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

#include <stddef.h>
#include <stdint.h>

namespace Crypto {

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

class TlsClientSession {
public:
  using Callback = void (*)(TlsAsyncStatus status, void *context);

  TlsClientSession();

  /**
   * @brief Store trust-anchor material lifetime supplied by the caller.
   *
   * Certificate parsing and verification belong to Mbed TLS. This API only
   * records the trust material pointer and length that a later Mbed TLS slice
   * will parse. The caller must keep the memory valid for the session lifetime.
   */
  bool configureTrustAnchors(const uint8_t *data, size_t length);

  /**
   * @brief Set the hostname used for SNI and certificate verification.
   */
  bool setHostname(const char *hostname);

  /**
   * @brief Bind the TLS BIO to an already-created non-blocking transport.
   */
  bool bindTransport(TlsTransport &transport);

  /**
   * @brief Start async TLS handshake progress.
   *
   * The call validates configuration and stores callback state only. `poll()`
   * reports `WaitingCrypto` until the owning Crypto/Mbed TLS adapter has
   * completed async seed/DRBG readiness and calls `markCryptoReady()`.
   */
  TlsAsyncStatus handshakeAsync(Callback callback, void *context = nullptr);

  /**
   * @brief Mark the async crypto prerequisites for handshake as ready.
   *
   * This is the handoff point from `MbedTlsPort` seed/DRBG setup into the TLS
   * session state machine. It exists so TLS handshake progress never calls a
   * blocking entropy or random callback. Future real Mbed TLS integration will
   * call this from the async crypto completion path after the Mbed TLS RNG
   * context is ready.
   */
  bool markCryptoReady();

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
   */
  TlsAsyncStatus poll();

  /**
   * @brief Abort session state without attempting close-notify.
   */
  void abort();

  TlsAsyncStatus status() const { return _status; }
  TlsOperation operation() const { return _operation; }
  int lastError() const { return _lastError; }
  uint32_t verificationResult() const { return _verificationResult; }
  bool configured() const;
  bool handshakeComplete() const { return _handshakeComplete; }
  size_t bytesTransferred() const { return _bytesTransferred; }

private:
  bool operationActive() const;
  bool startOperation(TlsOperation operation, Callback callback, void *context);
  TlsAsyncStatus finish(TlsAsyncStatus status);
  TlsAsyncStatus fail(int error);
  TlsAsyncStatus reject(int error);

  TlsTransport *_transport;
  const uint8_t *_trustAnchors;
  size_t _trustAnchorLength;
  const char *_hostname;
  TlsAsyncStatus _status;
  TlsOperation _operation;
  Callback _callback;
  void *_callbackContext;
  uint8_t *_readBuffer;
  const uint8_t *_writeBuffer;
  size_t _requestedLength;
  size_t _bytesTransferred;
  int _lastError;
  uint32_t _verificationResult;
  bool _handshakeComplete;
  bool _cryptoReady;
};

} // namespace Crypto
