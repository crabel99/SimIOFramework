#pragma once

#include <SecureClient.h>
#include <stddef.h>
#include <stdint.h>
#include <utility/network/NetworkClock.h>
#include <utility/transport/TransportProvider.h>

enum class TrustedTimeClientStatus : uint8_t {
  Idle = 0,
  Connecting = 1,
  Handshaking = 2,
  Requesting = 3,
  Receiving = 4,
  Updated = 5,
  Failed = 6,
};

enum class TrustedTimeClientError : uint8_t {
  None = 0,
  InvalidArgument = 1,
  TlsConfigurationFailed = 2,
  ConnectFailed = 3,
  TlsHandshakeFailed = 4,
  WriteFailed = 5,
  ResponseTooLarge = 6,
  InvalidResponse = 7,
  AuthenticationFailed = 8,
  ClockRejected = 9,
  OperationDeadlineExceeded = 10,
  CertificatePinMismatch = 11,
};

using TrustedTimeResponseAuthenticator =
    bool (*)(const uint8_t *body, size_t bodyLength, uint64_t unixTime,
             void *context);

/**
 * @brief Policy for a constrained authenticated HTTPS time source.
 *
 * The source is intentionally narrow: one configured host, port, path, trust
 * anchor set, TLS crypto provider, leaf certificate SHA-256 pin, and
 * provisional Unix time used only for this endpoint's certificate date
 * validation. The response authenticator must validate the exact body/time
 * before `NetworkClock` is promoted to trusted.
 *
 * @todo Add SPKI pinning once the TLS wrapper exposes the parsed peer
 * public-key DER. The current pin is the complete leaf certificate DER digest.
 */
struct TrustedTimeSourcePolicy {
  static constexpr size_t CertificateSha256Length =
      Crypto::TlsSha256DigestLength;

  const char *host = nullptr;
  IPAddress connectIp;
  bool connectByIp = false;
  uint16_t port = 443;
  const char *path = "/";
  const uint8_t *trustAnchors = nullptr;
  size_t trustAnchorLength = 0;
  const uint8_t *certificateSha256 = nullptr;
  size_t certificateSha256Length = 0;
  Crypto::TlsCryptoProvider *cryptoProvider = nullptr;
  uint64_t provisionalUnixTime = 0;
  TrustedTimeResponseAuthenticator authenticate = nullptr;
  void *authenticationContext = nullptr;

  bool valid() const {
    return host != nullptr && host[0] != '\0' &&
           (!connectByIp || connectIp != IPAddress()) && port != 0 && path != nullptr &&
           path[0] == '/' && trustAnchors != nullptr && trustAnchorLength != 0 &&
           certificateSha256 != nullptr &&
           certificateSha256Length == CertificateSha256Length &&
           cryptoProvider != nullptr && provisionalUnixTime >= 946684800ULL &&
           authenticate != nullptr;
  }
};

/**
 * @brief Bounded HTTPS client that promotes NetworkClock after authentication.
 *
 * `TrustedTimeClient` owns the `SecureClient` session used for bootstrap time.
 * It does not weaken general TLS policy: provisional time is applied only to
 * the configured time-source connection, and trusted clock promotion occurs
 * only after TLS succeeds and the response authenticator accepts the returned
 * Unix time.
 */
class TrustedTimeClient {
public:
  static constexpr size_t RequestCapacity = 160;
  static constexpr size_t ResponseCapacity = 384;
  static constexpr uint16_t DefaultPollLimit = 2000;

  TrustedTimeClient(TransportProvider &provider, NetworkClock &clock);

  bool begin(const TrustedTimeSourcePolicy &policy);
  bool setPollLimit(uint16_t pollLimit);
  TrustedTimeClientStatus poll();
  void stop();

  TrustedTimeClientStatus status() const { return _status; }
  TrustedTimeClientError lastError() const { return _lastError; }
  uint64_t receivedUnixTime() const { return _receivedUnixTime; }
  uint16_t pollLimit() const { return _pollLimit; }

  static bool parseHttpUnixTimeResponse(const uint8_t *response,
                                        size_t responseLength,
                                        const uint8_t *&bodyOut,
                                        size_t &bodyLengthOut,
                                        uint64_t &unixTimeOut);

private:
  TrustedTimeClientStatus fail(TrustedTimeClientError error);
  bool buildRequest(const char *host, const char *path);
  bool receiveAvailable();
  bool processResponse();
  bool active() const;
  bool consumePollBudget();

  NetworkClock &_clock;
  SecureClient _client;
  TrustedTimeSourcePolicy _policy = {};
  TrustedTimeClientStatus _status = TrustedTimeClientStatus::Idle;
  TrustedTimeClientError _lastError = TrustedTimeClientError::None;
  uint64_t _receivedUnixTime = 0;
  uint16_t _pollLimit = DefaultPollLimit;
  uint16_t _pollCount = 0;
  uint8_t _request[RequestCapacity] = {};
  size_t _requestLength = 0;
  uint8_t _response[ResponseCapacity] = {};
  size_t _responseLength = 0;
};
