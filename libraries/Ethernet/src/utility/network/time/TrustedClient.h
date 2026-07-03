#pragma once

#include <SecureClient.h>
#include <stddef.h>
#include <stdint.h>
#include <utility/network/time/Config.h>
#include <utility/transport/TransportProvider.h>

class NetworkTimeService;

enum class NetworkTimeTrustedClientStatus : uint8_t {
  Idle = 0,
  Connecting = 1,
  Handshaking = 2,
  Requesting = 3,
  Receiving = 4,
  Updated = 5,
  Failed = 6,
  Authenticating = 7,
};

enum class NetworkTimeTrustedClientError : uint8_t {
  None = 0,
  InvalidArgument = 1,
  TlsConfigurationFailed = 2,
  ConnectFailed = 3,
  TlsHandshakeFailed = 4,
  WriteFailed = 5,
  ResponseTooLarge = 6,
  InvalidResponse = 7,
  AuthenticationFailed = 8,
  TimeRejected = 9,
  OperationDeadlineExceeded = 10,
  CertificatePinMismatch = 11,
};

/**
 * @brief Bounded HTTPS client that promotes network time after authentication.
 *
 * `NetworkTimeTrustedClient` owns the `SecureClient` session used for
 * bootstrap time. It does not weaken general TLS policy: provisional time is
 * applied only to the configured time-source connection, and trusted clock
 * promotion occurs only after TLS succeeds and the response authenticator
 * accepts the returned Unix time.
 */
class NetworkTimeTrustedClient {
public:
  static constexpr size_t RequestCapacity = 160;
  static constexpr size_t ResponseCapacity = 384;
  static constexpr uint16_t DefaultPollLimit = 2000;

  NetworkTimeTrustedClient() = default;
  NetworkTimeTrustedClient(TransportProvider &provider,
                           NetworkTimeService &timeService);

  void attach(TransportProvider &provider, NetworkTimeService &timeService);

  bool begin(const NetworkTimeTrustedSourcePolicy &policy);
  bool setPollLimit(uint16_t pollLimit);
  NetworkTimeTrustedClientStatus poll();
  void stop();

  bool active() const;
  NetworkTimeTrustedClientStatus status() const { return _status; }
  NetworkTimeTrustedClientError lastError() const { return _lastError; }
  int tlsLastError() const { return _tlsLastError; }
  int tlsLastMbedTlsResult() const { return _tlsLastMbedTlsResult; }
  int tlsHandshakeState() const { return _tlsHandshakeState; }
  uint32_t tlsVerificationResult() const { return _tlsVerificationResult; }
  uint64_t receivedUnixTime() const { return _receivedUnixTime; }
  uint16_t pollLimit() const { return _pollLimit; }

  static bool parseHttpUnixTimeResponse(const uint8_t *response,
                                        size_t responseLength,
                                        const uint8_t *&bodyOut,
                                        size_t &bodyLengthOut,
                                        uint64_t &unixTimeOut);

private:
  NetworkTimeTrustedClientStatus fail(NetworkTimeTrustedClientError error);
  bool buildRequest(const char *host, const char *path);
  bool receiveAvailable();
  bool processResponse();
  bool authenticateResponse(const uint8_t *body, size_t bodyLength,
                            uint64_t unixTime);
  bool startResponseSignatureVerification(const uint8_t *body,
                                          size_t bodyLength, uint64_t unixTime);
  bool finishAuthenticatedResponse();
  static void handleResponseSignatureVerified(bool success, void *context);
  bool consumePollBudget();

  NetworkTimeService *_timeService = nullptr;
  SecureClient _client;
  NetworkTimeTrustedSourcePolicy _policy = {};
  NetworkTimeTrustedClientStatus _status = NetworkTimeTrustedClientStatus::Idle;
  NetworkTimeTrustedClientError _lastError =
      NetworkTimeTrustedClientError::None;
  uint64_t _receivedUnixTime = 0;
  uint16_t _pollLimit = DefaultPollLimit;
  uint16_t _pollCount = 0;
  uint8_t _request[RequestCapacity] = {};
  size_t _requestLength = 0;
  uint8_t _response[ResponseCapacity] = {};
  size_t _responseLength = 0;
  uint64_t _authenticatedUnixTime = 0;
  uint8_t _responseSignatureHash[Crypto::TlsSha256DigestLength] = {};
  uint8_t
      _responseSignature
          [NetworkTimeTrustedSourcePolicy::EcdsaP256SignatureLength] = {};
  bool _responseSignatureVerified = false;
  bool _responseSignatureComplete = false;
  int _tlsLastError = 0;
  int _tlsLastMbedTlsResult = 0;
  int _tlsHandshakeState = 0;
  uint32_t _tlsVerificationResult = 0;
};
