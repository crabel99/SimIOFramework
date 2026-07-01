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
  Authenticating = 7,
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
 * @brief HTTPS endpoint pin material checked before the time request is sent.
 *
 * Leaf certificate pins bind the policy to one exact certificate. SPKI pins
 * bind the policy to the certificate public key and allow normal certificate
 * renewal as long as the trusted endpoint keeps the same key.
 */
enum class TrustedTimePinKind : uint8_t {
  LeafCertificateSha256 = 0,
  SubjectPublicKeyInfoSha256 = 1,
};

/**
 * @brief Optional response signature algorithm for authenticated time bodies.
 *
 * `EcdsaP256Sha256` verifies a raw P1363 `R || S` signature over
 * SHA-256(response body) with the configured uncompressed P-256 public key.
 * Verification is started through `TlsCryptoProvider::signatureVerifyAsync()`;
 * provider absence, unsupported algorithms, failed starts, and bad signatures
 * fail closed without promoting `NetworkClock` to trusted.
 */
enum class TrustedTimeResponseSignatureAlgorithm : uint8_t {
  None = 0,
  EcdsaP256Sha256 = 1,
};

/**
 * @brief Policy for a constrained authenticated HTTPS time source.
 *
 * The source is intentionally narrow: one configured host, port, path, trust
 * anchor set, TLS crypto provider, SHA-256 endpoint pin, and
 * provisional Unix time used only for this endpoint's certificate date
 * validation.
 *
 * A policy must configure at least one response authenticator:
 * - `authenticate`, a caller callback that checks the exact parsed body/time.
 * - `responseSignatureAlgorithm`, which validates a signed response body
 *   through the async Crypto provider.
 *
 * If both are configured, both must accept the exact same response before
 * `NetworkClock` is promoted to trusted.
 */
struct TrustedTimeSourcePolicy {
  static constexpr size_t CertificateSha256Length =
      Crypto::TlsSha256DigestLength;
  static constexpr size_t EcdsaP256PublicKeyLength = 65;
  static constexpr size_t EcdsaP256SignatureLength = 64;

  /** Hostname used for SNI, hostname verification, and the HTTP Host header. */
  const char *host = nullptr;
  /** Optional literal endpoint address when DNS is not part of bootstrap. */
  IPAddress connectIp;
  /** Connect to `connectIp` while still validating `host` at the TLS layer. */
  bool connectByIp = false;
  uint16_t port = 443;
  /** Absolute HTTP path that returns a decimal Unix-time body. */
  const char *path = "/";
  const uint8_t *trustAnchors = nullptr;
  size_t trustAnchorLength = 0;
  /** Expected SHA-256 digest selected by `pinKind`. */
  const uint8_t *certificateSha256 = nullptr;
  size_t certificateSha256Length = 0;
  TrustedTimePinKind pinKind = TrustedTimePinKind::LeafCertificateSha256;
  TrustedTimeResponseSignatureAlgorithm responseSignatureAlgorithm =
      TrustedTimeResponseSignatureAlgorithm::None;
  /** Header containing a lowercase or uppercase hex-encoded raw signature. */
  const char *responseSignatureHeader = "X-SimIO-Time-Signature";
  /** Uncompressed P-256 public key: 0x04 || X || Y. */
  const uint8_t *responseSigningPublicKey = nullptr;
  size_t responseSigningPublicKeyLength = 0;
  Crypto::TlsCryptoProvider *cryptoProvider = nullptr;
  /** Plausible time used only for this endpoint's certificate date checks. */
  uint64_t provisionalUnixTime = 0;
  TrustedTimeResponseAuthenticator authenticate = nullptr;
  void *authenticationContext = nullptr;

  bool valid() const {
    const bool hasCallbackAuthenticator = authenticate != nullptr;
    const bool hasResponseSignature =
        responseSignatureAlgorithm !=
            TrustedTimeResponseSignatureAlgorithm::None &&
        responseSignatureHeader != nullptr &&
        responseSignatureHeader[0] != '\0' &&
        responseSigningPublicKey != nullptr &&
        responseSigningPublicKeyLength == EcdsaP256PublicKeyLength;

    return host != nullptr && host[0] != '\0' &&
           (!connectByIp || connectIp != IPAddress()) && port != 0 &&
           path != nullptr && path[0] == '/' && trustAnchors != nullptr &&
           trustAnchorLength != 0 && certificateSha256 != nullptr &&
           certificateSha256Length == CertificateSha256Length &&
           cryptoProvider != nullptr && provisionalUnixTime >= 946684800ULL &&
           (hasCallbackAuthenticator || hasResponseSignature);
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
  bool authenticateResponse(const uint8_t *body, size_t bodyLength,
                            uint64_t unixTime);
  bool startResponseSignatureVerification(const uint8_t *body,
                                          size_t bodyLength, uint64_t unixTime);
  bool finishAuthenticatedResponse();
  static void handleResponseSignatureVerified(bool success, void *context);
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
  uint64_t _authenticatedUnixTime = 0;
  uint8_t _responseSignatureHash[Crypto::TlsSha256DigestLength] = {};
  uint8_t
      _responseSignature[TrustedTimeSourcePolicy::EcdsaP256SignatureLength] =
          {};
  bool _responseSignatureVerified = false;
  bool _responseSignatureComplete = false;
};
