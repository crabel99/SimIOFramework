#include "TrustedClient.h"

#include <psa/crypto.h>
#include <utility/network/TimeService.h>
#include <string.h>

namespace {
constexpr char HeaderTerminator[] = "\r\n\r\n";
constexpr char ContentLengthHeader[] = "Content-Length:";
constexpr uint64_t MinTrustedUnixTime = 946684800ULL;

bool appendLiteral(uint8_t *buffer, size_t capacity, size_t &length,
                   const char *text) {
  const size_t textLength = strlen(text);
  if (length + textLength > capacity)
    return false;

  memcpy(buffer + length, text, textLength);
  length += textLength;
  return true;
}

const uint8_t *findBytes(const uint8_t *buffer, size_t length,
                         const char *needle) {
  const size_t needleLength = strlen(needle);
  if (buffer == nullptr || needleLength == 0 || length < needleLength)
    return nullptr;

  for (size_t index = 0; index <= length - needleLength; ++index) {
    if (memcmp(buffer + index, needle, needleLength) == 0)
      return buffer + index;
  }
  return nullptr;
}

bool parseUnsignedDecimal(const uint8_t *buffer, size_t length,
                          uint64_t &valueOut) {
  if (buffer == nullptr || length == 0)
    return false;

  size_t index = 0;
  while (index < length && (buffer[index] == ' ' || buffer[index] == '\r' ||
                            buffer[index] == '\n' || buffer[index] == '\t')) {
    ++index;
  }
  if (index == length || buffer[index] < '0' || buffer[index] > '9')
    return false;

  uint64_t value = 0;
  while (index < length && buffer[index] >= '0' && buffer[index] <= '9') {
    const uint64_t next =
        value * 10 + static_cast<uint64_t>(buffer[index] - '0');
    if (next < value)
      return false;
    value = next;
    ++index;
  }

  valueOut = value;
  return value >= MinTrustedUnixTime;
}

bool parseContentLength(const uint8_t *headers, size_t length,
                        size_t &contentLengthOut) {
  const uint8_t *header = findBytes(headers, length, ContentLengthHeader);
  if (header == nullptr)
    return false;

  header += strlen(ContentLengthHeader);
  const uint8_t *end = headers + length;
  while (header < end && (*header == ' ' || *header == '\t'))
    ++header;

  size_t value = 0;
  bool sawDigit = false;
  while (header < end && *header >= '0' && *header <= '9') {
    sawDigit = true;
    const size_t next = value * 10 + static_cast<size_t>(*header - '0');
    if (next < value)
      return false;
    value = next;
    ++header;
  }

  if (!sawDigit)
    return false;

  contentLengthOut = value;
  return true;
}

bool constantTimeEqual(const uint8_t *left, const uint8_t *right,
                       size_t length) {
  if (left == nullptr || right == nullptr || length == 0)
    return false;

  uint8_t diff = 0;
  for (size_t index = 0; index < length; ++index)
    diff |= static_cast<uint8_t>(left[index] ^ right[index]);

  return diff == 0;
}

int hexValue(uint8_t value) {
  if (value >= '0' && value <= '9')
    return static_cast<int>(value - '0');
  if (value >= 'a' && value <= 'f')
    return static_cast<int>(value - 'a' + 10);
  if (value >= 'A' && value <= 'F')
    return static_cast<int>(value - 'A' + 10);
  return -1;
}

uint8_t asciiLower(uint8_t value) {
  return value >= 'A' && value <= 'Z' ? static_cast<uint8_t>(value + 32)
                                      : value;
}

bool headerNameEquals(const uint8_t *line, size_t lineLength,
                      const char *headerName) {
  const size_t headerNameLength = strlen(headerName);
  if (line == nullptr || lineLength <= headerNameLength ||
      line[headerNameLength] != ':') {
    return false;
  }

  for (size_t index = 0; index < headerNameLength; ++index) {
    if (asciiLower(line[index]) !=
        asciiLower(static_cast<uint8_t>(headerName[index]))) {
      return false;
    }
  }
  return true;
}

bool parseHexHeader(const uint8_t *headers, size_t headersLength,
                    const char *headerName, uint8_t *output,
                    size_t outputLength) {
  if (headers == nullptr || headerName == nullptr || headerName[0] == '\0' ||
      output == nullptr || outputLength == 0) {
    return false;
  }

  size_t lineStart = 0;
  while (lineStart < headersLength) {
    size_t lineEnd = lineStart;
    while (lineEnd < headersLength && headers[lineEnd] != '\r' &&
           headers[lineEnd] != '\n') {
      ++lineEnd;
    }

    const uint8_t *line = headers + lineStart;
    const size_t lineLength = lineEnd - lineStart;
    if (headerNameEquals(line, lineLength, headerName)) {
      size_t valueIndex = strlen(headerName) + 1;
      while (valueIndex < lineLength &&
             (line[valueIndex] == ' ' || line[valueIndex] == '\t')) {
        ++valueIndex;
      }

      if (lineLength - valueIndex < outputLength * 2)
        return false;

      for (size_t index = 0; index < outputLength; ++index) {
        const int high = hexValue(line[valueIndex + index * 2]);
        const int low = hexValue(line[valueIndex + index * 2 + 1]);
        if (high < 0 || low < 0)
          return false;
        output[index] = static_cast<uint8_t>((high << 4) | low);
      }

      valueIndex += outputLength * 2;
      while (valueIndex < lineLength &&
             (line[valueIndex] == ' ' || line[valueIndex] == '\t')) {
        ++valueIndex;
      }
      return valueIndex == lineLength;
    }

    lineStart = lineEnd;
    while (lineStart < headersLength &&
           (headers[lineStart] == '\r' || headers[lineStart] == '\n')) {
      ++lineStart;
    }
  }

  return false;
}

bool readPeerPin(
    SecureClient &client, NetworkTimeTrustedPinKind pinKind,
    uint8_t digest[NetworkTimeTrustedSourcePolicy::CertificateSha256Length]) {
  switch (pinKind) {
  case NetworkTimeTrustedPinKind::LeafCertificateSha256:
    return client.peerCertificateSha256(digest);
  case NetworkTimeTrustedPinKind::SubjectPublicKeyInfoSha256:
    return client.peerSubjectPublicKeyInfoSha256(digest);
  default:
    return false;
  }
}
} // namespace

NetworkTimeTrustedClient::NetworkTimeTrustedClient(TransportProvider &provider,
                                     NetworkTimeService &timeService)
    : _client(provider) {
  attach(provider, timeService);
}

void NetworkTimeTrustedClient::attach(TransportProvider &provider,
                               NetworkTimeService &timeService) {
  _client.setTransportProvider(provider);
  _timeService = &timeService;
}

bool NetworkTimeTrustedClient::begin(const NetworkTimeTrustedSourcePolicy &policy) {
  if (_timeService == nullptr) {
    _lastError = NetworkTimeTrustedClientError::InvalidArgument;
    return false;
  }
  if (active()) {
    _lastError = NetworkTimeTrustedClientError::InvalidArgument;
    return false;
  }
  if (!policy.valid()) {
    _lastError = NetworkTimeTrustedClientError::InvalidArgument;
    return false;
  }
  if (!buildRequest(policy.host, policy.path)) {
    _lastError = NetworkTimeTrustedClientError::InvalidArgument;
    return false;
  }

  uint64_t provisionalUnixTime = policy.provisionalUnixTime;
  if (provisionalUnixTime == 0) {
    const NetworkTimeSnapshot snapshot = _timeService->unixTime();
    if (!snapshot.valid() || snapshot.unixTime < MinTrustedUnixTime) {
      _lastError = NetworkTimeTrustedClientError::InvalidArgument;
      return false;
    }
    provisionalUnixTime = snapshot.unixTime;
  }

  NetworkTimeTrustedSourcePolicy resolvedPolicy = policy;
  resolvedPolicy.provisionalUnixTime = provisionalUnixTime;

  if (!_client.setCryptoProvider(*resolvedPolicy.cryptoProvider)) {
    _lastError = NetworkTimeTrustedClientError::TlsConfigurationFailed;
    return false;
  }
  _client.stop();
  if (!_client.setTlsSecurityLevel(SecureClientTlsSecurityLevel::Medium) ||
      !_client.setCryptoProvider(*resolvedPolicy.cryptoProvider) ||
      !_client.setTrustAnchors(resolvedPolicy.trustAnchors,
                               resolvedPolicy.trustAnchorLength) ||
      !_client.setTrustedTime(resolvedPolicy.provisionalUnixTime) ||
      !_client.setHostname(resolvedPolicy.host)) {
    _lastError = NetworkTimeTrustedClientError::TlsConfigurationFailed;
    return false;
  }

  const int connectResult =
      resolvedPolicy.connectByIp
          ? _client.connect(resolvedPolicy.connectIp, resolvedPolicy.port)
          : _client.connect(resolvedPolicy.host, resolvedPolicy.port);
  if (connectResult != 1) {
    _lastError = NetworkTimeTrustedClientError::ConnectFailed;
    return false;
  }

  _policy = resolvedPolicy;
  _status = NetworkTimeTrustedClientStatus::Handshaking;
  _lastError = NetworkTimeTrustedClientError::None;
  _receivedUnixTime = 0;
  _responseLength = 0;
  _pollCount = 0;
  _authenticatedUnixTime = 0;
  _responseSignatureVerified = false;
  _responseSignatureComplete = false;
  _tlsLastError = 0;
  _tlsLastMbedTlsResult = 0;
  _tlsHandshakeState = 0;
  _tlsVerificationResult = 0;
  memset(_responseSignatureHash, 0, sizeof(_responseSignatureHash));
  memset(_responseSignature, 0, sizeof(_responseSignature));
  return true;
}

bool NetworkTimeTrustedClient::setPollLimit(uint16_t pollLimit) {
  if (active() || pollLimit == 0)
    return false;

  _pollLimit = pollLimit;
  return true;
}

NetworkTimeTrustedClientStatus NetworkTimeTrustedClient::poll() {
  if (active() && !consumePollBudget())
    return fail(NetworkTimeTrustedClientError::OperationDeadlineExceeded);

  switch (_status) {
  case NetworkTimeTrustedClientStatus::Handshaking: {
    const Crypto::TlsAsyncStatus tlsStatus = _client.pollTls();
    if (_client.connected()) {
      uint8_t peerPin[NetworkTimeTrustedSourcePolicy::CertificateSha256Length] = {};
      const bool pinAccepted =
          readPeerPin(_client, _policy.pinKind, peerPin) &&
          constantTimeEqual(peerPin, _policy.certificateSha256,
                            _policy.certificateSha256Length);
      memset(peerPin, 0, sizeof(peerPin));
      if (!pinAccepted)
        return fail(NetworkTimeTrustedClientError::CertificatePinMismatch);

      _status = NetworkTimeTrustedClientStatus::Requesting;
      return poll();
    }
    if (tlsStatus == Crypto::TlsAsyncStatus::Error ||
        _client.lastError() != SecureClientNoError) {
      return fail(NetworkTimeTrustedClientError::TlsHandshakeFailed);
    }
    return _status;
  }
  case NetworkTimeTrustedClientStatus::Requesting:
    if (_client.write(_request, _requestLength) != _requestLength)
      return fail(NetworkTimeTrustedClientError::WriteFailed);
    _status = NetworkTimeTrustedClientStatus::Receiving;
    return _status;
  case NetworkTimeTrustedClientStatus::Receiving:
    if (!receiveAvailable())
      return _status;
    processResponse();
    return _status;
  case NetworkTimeTrustedClientStatus::Authenticating:
    if (!_responseSignatureComplete)
      return _status;
    if (!_responseSignatureVerified)
      return fail(NetworkTimeTrustedClientError::AuthenticationFailed);
    finishAuthenticatedResponse();
    return _status;
  case NetworkTimeTrustedClientStatus::Idle:
  case NetworkTimeTrustedClientStatus::Connecting:
  case NetworkTimeTrustedClientStatus::Updated:
  case NetworkTimeTrustedClientStatus::Failed:
  default:
    return _status;
  }
}

void NetworkTimeTrustedClient::stop() {
  if (active())
    _client.stop();
  _status = NetworkTimeTrustedClientStatus::Idle;
  _lastError = NetworkTimeTrustedClientError::None;
  _receivedUnixTime = 0;
  _requestLength = 0;
  _responseLength = 0;
  _pollCount = 0;
  _authenticatedUnixTime = 0;
  _responseSignatureVerified = false;
  _responseSignatureComplete = false;
  _tlsLastError = 0;
  _tlsLastMbedTlsResult = 0;
  _tlsHandshakeState = 0;
  _tlsVerificationResult = 0;
  memset(_responseSignatureHash, 0, sizeof(_responseSignatureHash));
  memset(_responseSignature, 0, sizeof(_responseSignature));
}

bool NetworkTimeTrustedClient::parseHttpUnixTimeResponse(const uint8_t *response,
                                                  size_t responseLength,
                                                  const uint8_t *&bodyOut,
                                                  size_t &bodyLengthOut,
                                                  uint64_t &unixTimeOut) {
  bodyOut = nullptr;
  bodyLengthOut = 0;
  unixTimeOut = 0;

  if (response == nullptr)
    return false;
  const char okPrefix[] = "HTTP/1.1 200";
  const char okPrefix10[] = "HTTP/1.0 200";
  if (responseLength < strlen(okPrefix) ||
      (memcmp(response, okPrefix, strlen(okPrefix)) != 0 &&
       memcmp(response, okPrefix10, strlen(okPrefix10)) != 0)) {
    return false;
  }

  const uint8_t *headerEnd =
      findBytes(response, responseLength, HeaderTerminator);
  if (headerEnd == nullptr)
    return false;

  const size_t headerLength = static_cast<size_t>(headerEnd - response);
  const size_t bodyOffset = headerLength + strlen(HeaderTerminator);
  if (bodyOffset > responseLength)
    return false;

  size_t expectedBodyLength = 0;
  if (!parseContentLength(response, headerLength, expectedBodyLength))
    return false;
  if (expectedBodyLength > responseLength - bodyOffset)
    return false;

  const uint8_t *body = response + bodyOffset;
  uint64_t unixTime = 0;
  if (!parseUnsignedDecimal(body, expectedBodyLength, unixTime))
    return false;

  bodyOut = body;
  bodyLengthOut = expectedBodyLength;
  unixTimeOut = unixTime;
  return true;
}

NetworkTimeTrustedClientStatus NetworkTimeTrustedClient::fail(NetworkTimeTrustedClientError error) {
  _tlsLastError = _client.tlsLastError();
  _tlsLastMbedTlsResult = _client.tlsLastMbedTlsResult();
  _tlsHandshakeState = _client.tlsHandshakeState();
  _tlsVerificationResult = _client.tlsVerificationResult();
  _client.stop();
  _status = NetworkTimeTrustedClientStatus::Failed;
  _lastError = error;
  return _status;
}

bool NetworkTimeTrustedClient::buildRequest(const char *host, const char *path) {
  memset(_request, 0, sizeof(_request));
  _requestLength = 0;

  return appendLiteral(_request, sizeof(_request), _requestLength, "GET ") &&
         appendLiteral(_request, sizeof(_request), _requestLength, path) &&
         appendLiteral(_request, sizeof(_request), _requestLength,
                       " HTTP/1.1\r\nHost: ") &&
         appendLiteral(_request, sizeof(_request), _requestLength, host) &&
         appendLiteral(_request, sizeof(_request), _requestLength,
                       "\r\nConnection: close\r\nAccept: text/plain\r\n\r\n");
}

bool NetworkTimeTrustedClient::receiveAvailable() {
  _client.pollTls();

  while (_client.available() > 0) {
    if (_responseLength >= sizeof(_response)) {
      fail(NetworkTimeTrustedClientError::ResponseTooLarge);
      return false;
    }

    const int value = _client.read();
    if (value < 0)
      break;
    _response[_responseLength++] = static_cast<uint8_t>(value);
  }

  const uint8_t *body = nullptr;
  size_t bodyLength = 0;
  uint64_t unixTime = 0;
  if (parseHttpUnixTimeResponse(_response, _responseLength, body, bodyLength,
                                unixTime)) {
    return true;
  }

  if (!_client.connected() && _responseLength != 0) {
    fail(NetworkTimeTrustedClientError::InvalidResponse);
    return false;
  }
  if (!_client.connected() && _responseLength == 0) {
    fail(NetworkTimeTrustedClientError::InvalidResponse);
    return false;
  }

  return false;
}

bool NetworkTimeTrustedClient::processResponse() {
  const uint8_t *body = nullptr;
  size_t bodyLength = 0;
  uint64_t unixTime = 0;
  if (!parseHttpUnixTimeResponse(_response, _responseLength, body, bodyLength,
                                 unixTime)) {
    fail(NetworkTimeTrustedClientError::InvalidResponse);
    return false;
  }

  if (!authenticateResponse(body, bodyLength, unixTime)) {
    fail(NetworkTimeTrustedClientError::AuthenticationFailed);
    return false;
  }

  return true;
}

bool NetworkTimeTrustedClient::authenticateResponse(const uint8_t *body,
                                             size_t bodyLength,
                                             uint64_t unixTime) {
  if (_policy.authenticate != nullptr &&
      !_policy.authenticate(body, bodyLength, unixTime,
                            _policy.authenticationContext)) {
    return false;
  }

  if (_policy.responseSignatureAlgorithm ==
      NetworkTimeTrustedResponseSignatureAlgorithm::None) {
    _authenticatedUnixTime = unixTime;
    return finishAuthenticatedResponse();
  }

  return startResponseSignatureVerification(body, bodyLength, unixTime);
}

bool NetworkTimeTrustedClient::startResponseSignatureVerification(const uint8_t *body,
                                                           size_t bodyLength,
                                                           uint64_t unixTime) {
  if (_policy.responseSignatureAlgorithm !=
      NetworkTimeTrustedResponseSignatureAlgorithm::EcdsaP256Sha256) {
    return false;
  }

  const uint8_t *headerEnd =
      findBytes(_response, _responseLength, HeaderTerminator);
  if (headerEnd == nullptr)
    return false;

  const size_t headerLength = static_cast<size_t>(headerEnd - _response);
  if (!parseHexHeader(_response, headerLength, _policy.responseSignatureHeader,
                      _responseSignature, sizeof(_responseSignature))) {
    return false;
  }

  size_t hashLength = 0;
  if (psa_crypto_init() != PSA_SUCCESS ||
      psa_hash_compute(PSA_ALG_SHA_256, body, bodyLength,
                       _responseSignatureHash, sizeof(_responseSignatureHash),
                       &hashLength) != PSA_SUCCESS ||
      hashLength != sizeof(_responseSignatureHash)) {
    return false;
  }

  _authenticatedUnixTime = unixTime;
  _responseSignatureVerified = false;
  _responseSignatureComplete = false;
  _status = NetworkTimeTrustedClientStatus::Authenticating;

  if (!_policy.cryptoProvider->signatureVerifyAsync(
          Crypto::TlsSignatureAlgorithm::EcdsaP256Sha256,
          _policy.responseSigningPublicKey,
          _policy.responseSigningPublicKeyLength, _responseSignatureHash,
          sizeof(_responseSignatureHash), _responseSignature,
          sizeof(_responseSignature), handleResponseSignatureVerified, this)) {
    memset(_responseSignatureHash, 0, sizeof(_responseSignatureHash));
    memset(_responseSignature, 0, sizeof(_responseSignature));
    return false;
  }

  return true;
}

bool NetworkTimeTrustedClient::finishAuthenticatedResponse() {
  if (_timeService == nullptr ||
      !_timeService->applyTime(_authenticatedUnixTime,
                               NetworkTimeLevel::Trusted)) {
    fail(NetworkTimeTrustedClientError::TimeRejected);
    return false;
  }

  _receivedUnixTime = _authenticatedUnixTime;
  _client.stop();
  _status = NetworkTimeTrustedClientStatus::Updated;
  _lastError = NetworkTimeTrustedClientError::None;
  memset(_responseSignatureHash, 0, sizeof(_responseSignatureHash));
  memset(_responseSignature, 0, sizeof(_responseSignature));
  return true;
}

void NetworkTimeTrustedClient::handleResponseSignatureVerified(bool success,
                                                        void *context) {
  auto *client = static_cast<NetworkTimeTrustedClient *>(context);
  if (client == nullptr)
    return;

  client->_responseSignatureVerified = success;
  client->_responseSignatureComplete = true;
  if (!success) {
    memset(client->_responseSignatureHash, 0,
           sizeof(client->_responseSignatureHash));
    memset(client->_responseSignature, 0, sizeof(client->_responseSignature));
  }
}

bool NetworkTimeTrustedClient::active() const {
  return _status == NetworkTimeTrustedClientStatus::Connecting ||
         _status == NetworkTimeTrustedClientStatus::Handshaking ||
         _status == NetworkTimeTrustedClientStatus::Requesting ||
         _status == NetworkTimeTrustedClientStatus::Receiving ||
         _status == NetworkTimeTrustedClientStatus::Authenticating;
}

bool NetworkTimeTrustedClient::consumePollBudget() {
  if (_pollLimit == 0)
    return false;
  if (_pollCount >= _pollLimit)
    return false;

  ++_pollCount;
  return true;
}
