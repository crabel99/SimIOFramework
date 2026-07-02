#pragma once

#include <IPAddress.h>
#include <stddef.h>
#include <stdint.h>
#include <utility/tls/TlsClientSession.h>

enum class NetworkTimeLevel : uint8_t {
  Unset = 0,
  // Manual and provisional time share the same TLS trust rank. Manual time is
  // local/user supplied; provisional time is network supplied but not trusted.
  Manual = 2,
  Provisional = 2,
  Trusted = 3,
  Gps = 4,
};

enum class NetworkTimeServiceStatus : uint8_t {
  Stopped = 0,
  Ready = 1,
  TimeSet = 2,
  RtcUnavailable = 3,
  SourceUpdatePending = 4,
  SourceUpdateFailed = 5,
};

enum NetworkTimeWarning : uint16_t {
  NetworkTimeWarningNone = 0,
  NetworkTimeWarningLowerTrustUpdateRejected = 1u << 0,
  NetworkTimeWarningRtcSetFailed = 1u << 1,
  NetworkTimeWarningProvisionalSourceFailed = 1u << 2,
  NetworkTimeWarningTrustedSourceFailed = 1u << 3,
  NetworkTimeWarningRtcReadFailed = 1u << 4,
};

struct NetworkTimeSnapshot {
  uint64_t unixTime = 0;
  NetworkTimeLevel trustLevel = NetworkTimeLevel::Unset;
  NetworkTimeLevel highestConnectedLevel = NetworkTimeLevel::Unset;
  NetworkTimeServiceStatus status = NetworkTimeServiceStatus::Stopped;
  uint16_t warnings = NetworkTimeWarningNone;

  bool valid() const {
    return unixTime != 0 && trustLevel != NetworkTimeLevel::Unset;
  }

  bool satisfies(NetworkTimeLevel required) const {
    return valid() &&
           static_cast<uint8_t>(trustLevel) >= static_cast<uint8_t>(required);
  }
};

struct NetworkTimeProvisionalSource {
  static constexpr uint16_t DefaultServerPort = 123;
  static constexpr uint16_t DefaultLocalPort = 0;

  IPAddress server;
  uint16_t serverPort = DefaultServerPort;
  uint16_t localPort = DefaultLocalPort;

  bool configured() const { return server != IPAddress() && serverPort != 0; }
};

using NetworkTimeTrustedResponseAuthenticator =
    bool (*)(const uint8_t *body, size_t bodyLength, uint64_t unixTime,
             void *context);

enum class NetworkTimeTrustedPinKind : uint8_t {
  LeafCertificateSha256 = 0,
  SubjectPublicKeyInfoSha256 = 1,
};

enum class NetworkTimeTrustedResponseSignatureAlgorithm : uint8_t {
  None = 0,
  EcdsaP256Sha256 = 1,
};

struct NetworkTimeTrustedSourcePolicy {
  static constexpr size_t CertificateSha256Length =
      Crypto::TlsSha256DigestLength;
  static constexpr size_t EcdsaP256PublicKeyLength = 65;
  static constexpr size_t EcdsaP256SignatureLength = 64;

  const char *host = nullptr;
  IPAddress connectIp;
  bool connectByIp = false;
  uint16_t port = 443;
  const char *path = "/";
  const uint8_t *trustAnchors = nullptr;
  size_t trustAnchorLength = 0;
  const uint8_t *certificateSha256 = nullptr;
  size_t certificateSha256Length = 0;
  NetworkTimeTrustedPinKind pinKind =
      NetworkTimeTrustedPinKind::LeafCertificateSha256;
  NetworkTimeTrustedResponseSignatureAlgorithm responseSignatureAlgorithm =
      NetworkTimeTrustedResponseSignatureAlgorithm::None;
  const char *responseSignatureHeader = "X-Arduino-Time-Signature";
  const uint8_t *responseSigningPublicKey = nullptr;
  size_t responseSigningPublicKeyLength = 0;
  Crypto::TlsCryptoProvider *cryptoProvider = nullptr;
  uint64_t provisionalUnixTime = 0;
  NetworkTimeTrustedResponseAuthenticator authenticate = nullptr;
  void *authenticationContext = nullptr;

  bool valid() const {
    const bool hasCallbackAuthenticator = authenticate != nullptr;
    const bool hasResponseSignature =
        responseSignatureAlgorithm !=
            NetworkTimeTrustedResponseSignatureAlgorithm::None &&
        responseSignatureHeader != nullptr &&
        responseSignatureHeader[0] != '\0' &&
        responseSigningPublicKey != nullptr &&
        responseSigningPublicKeyLength == EcdsaP256PublicKeyLength;

    return host != nullptr && host[0] != '\0' &&
           (!connectByIp || connectIp != IPAddress()) && port != 0 &&
           path != nullptr && path[0] == '/' && trustAnchors != nullptr &&
           trustAnchorLength != 0 && certificateSha256 != nullptr &&
           certificateSha256Length == CertificateSha256Length &&
           cryptoProvider != nullptr &&
           (provisionalUnixTime == 0 ||
            provisionalUnixTime >= 946684800ULL) &&
           (hasCallbackAuthenticator || hasResponseSignature);
  }
};
