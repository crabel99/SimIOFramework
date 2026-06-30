#include "TrustedTimeClient.h"

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
  while (index < length &&
         (buffer[index] == ' ' || buffer[index] == '\r' ||
          buffer[index] == '\n' || buffer[index] == '\t')) {
    ++index;
  }
  if (index == length || buffer[index] < '0' || buffer[index] > '9')
    return false;

  uint64_t value = 0;
  while (index < length && buffer[index] >= '0' && buffer[index] <= '9') {
    const uint64_t next = value * 10 + static_cast<uint64_t>(buffer[index] - '0');
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
} // namespace

TrustedTimeClient::TrustedTimeClient(TransportProvider &provider,
                                     NetworkClock &clock)
    : _clock(clock), _client(provider) {}

bool TrustedTimeClient::begin(const TrustedTimeSourcePolicy &policy) {
  if (active()) {
    _lastError = TrustedTimeClientError::InvalidArgument;
    return false;
  }
  if (!policy.valid()) {
    _lastError = TrustedTimeClientError::InvalidArgument;
    return false;
  }
  if (!buildRequest(policy.host, policy.path)) {
    _lastError = TrustedTimeClientError::InvalidArgument;
    return false;
  }

  _client.stop();
  if (!_client.setCryptoProvider(*policy.cryptoProvider) ||
      !_client.setTrustAnchors(policy.trustAnchors, policy.trustAnchorLength) ||
      !_client.setTrustedTime(policy.provisionalUnixTime) ||
      !_client.setHostname(policy.host)) {
    _lastError = TrustedTimeClientError::TlsConfigurationFailed;
    return false;
  }

  if (_client.connect(policy.host, policy.port) != 1) {
    _lastError = TrustedTimeClientError::ConnectFailed;
    return false;
  }

  _policy = policy;
  _status = TrustedTimeClientStatus::Handshaking;
  _lastError = TrustedTimeClientError::None;
  _receivedUnixTime = 0;
  _responseLength = 0;
  _pollCount = 0;
  return true;
}

bool TrustedTimeClient::setPollLimit(uint16_t pollLimit) {
  if (active() || pollLimit == 0)
    return false;

  _pollLimit = pollLimit;
  return true;
}

TrustedTimeClientStatus TrustedTimeClient::poll() {
  if (active() && !consumePollBudget())
    return fail(TrustedTimeClientError::OperationDeadlineExceeded);

  switch (_status) {
  case TrustedTimeClientStatus::Handshaking: {
    const Crypto::TlsAsyncStatus tlsStatus = _client.pollTls();
    if (_client.connected()) {
      _status = TrustedTimeClientStatus::Requesting;
      return poll();
    }
    if (tlsStatus == Crypto::TlsAsyncStatus::Error ||
        _client.lastError() != SecureClientNoError) {
      return fail(TrustedTimeClientError::TlsHandshakeFailed);
    }
    return _status;
  }
  case TrustedTimeClientStatus::Requesting:
    if (_client.write(_request, _requestLength) != _requestLength)
      return fail(TrustedTimeClientError::WriteFailed);
    _status = TrustedTimeClientStatus::Receiving;
    return _status;
  case TrustedTimeClientStatus::Receiving:
    if (!receiveAvailable())
      return _status;
    processResponse();
    return _status;
  case TrustedTimeClientStatus::Idle:
  case TrustedTimeClientStatus::Connecting:
  case TrustedTimeClientStatus::Updated:
  case TrustedTimeClientStatus::Failed:
  default:
    return _status;
  }
}

void TrustedTimeClient::stop() {
  _client.stop();
  _status = TrustedTimeClientStatus::Idle;
  _lastError = TrustedTimeClientError::None;
  _receivedUnixTime = 0;
  _requestLength = 0;
  _responseLength = 0;
  _pollCount = 0;
}

bool TrustedTimeClient::parseHttpUnixTimeResponse(const uint8_t *response,
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

TrustedTimeClientStatus TrustedTimeClient::fail(TrustedTimeClientError error) {
  _client.stop();
  _status = TrustedTimeClientStatus::Failed;
  _lastError = error;
  return _status;
}

bool TrustedTimeClient::buildRequest(const char *host, const char *path) {
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

bool TrustedTimeClient::receiveAvailable() {
  _client.pollTls();

  while (_client.available() > 0) {
    if (_responseLength >= sizeof(_response)) {
      fail(TrustedTimeClientError::ResponseTooLarge);
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
    fail(TrustedTimeClientError::InvalidResponse);
    return false;
  }
  if (!_client.connected() && _responseLength == 0) {
    fail(TrustedTimeClientError::InvalidResponse);
    return false;
  }

  return false;
}

bool TrustedTimeClient::processResponse() {
  const uint8_t *body = nullptr;
  size_t bodyLength = 0;
  uint64_t unixTime = 0;
  if (!parseHttpUnixTimeResponse(_response, _responseLength, body, bodyLength,
                                 unixTime)) {
    fail(TrustedTimeClientError::InvalidResponse);
    return false;
  }

  if (!_policy.authenticate(body, bodyLength, unixTime,
                            _policy.authenticationContext)) {
    fail(TrustedTimeClientError::AuthenticationFailed);
    return false;
  }

  if (!_clock.setUnixTime(unixTime, NetworkTimeState::Trusted)) {
    fail(TrustedTimeClientError::ClockRejected);
    return false;
  }

  _receivedUnixTime = unixTime;
  _client.stop();
  _status = TrustedTimeClientStatus::Updated;
  _lastError = TrustedTimeClientError::None;
  return true;
}

bool TrustedTimeClient::active() const {
  return _status == TrustedTimeClientStatus::Connecting ||
         _status == TrustedTimeClientStatus::Handshaking ||
         _status == TrustedTimeClientStatus::Requesting ||
         _status == TrustedTimeClientStatus::Receiving;
}

bool TrustedTimeClient::consumePollBudget() {
  if (_pollLimit == 0)
    return false;
  if (_pollCount >= _pollLimit)
    return false;

  ++_pollCount;
  return true;
}
