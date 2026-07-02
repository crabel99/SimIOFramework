#include "SecureClient.h"

#include <string.h>
#include <utility/network/TimeService.h>

SecureClient::SecureClient()
    : EthernetClient(), _lastError(SecureClientNoError), _trustAnchors(nullptr),
      _trustAnchorLength(0), _clientCertificate(nullptr),
      _clientCertificateLength(0), _clientPrivateKey(nullptr),
      _clientPrivateKeyLength(0), _alpnProtocols(nullptr), _trustedUnixTime(0),
      _tlsOperationPollLimit(Crypto::DefaultTlsOperationPollLimit),
      _tlsSecurityLevel(SecureClientTlsSecurityLevel::High),
      _tlsSessionReuseEnabled(false), _tlsHandshakePending(false),
      _trustedTimeConfigured(false), _hostname{}, _cryptoProvider(nullptr),
      _lastTlsCallbackStatus(Crypto::TlsAsyncStatus::Idle) {}

SecureClient::SecureClient(EthernetSocket &socket)
    : EthernetClient(socket), _lastError(SecureClientNoError),
      _trustAnchors(nullptr), _trustAnchorLength(0),
      _clientCertificate(nullptr), _clientCertificateLength(0),
      _clientPrivateKey(nullptr), _clientPrivateKeyLength(0),
      _alpnProtocols(nullptr), _trustedUnixTime(0),
      _tlsOperationPollLimit(Crypto::DefaultTlsOperationPollLimit),
      _tlsSecurityLevel(SecureClientTlsSecurityLevel::High),
      _tlsSessionReuseEnabled(false), _tlsHandshakePending(false),
      _trustedTimeConfigured(false), _hostname{}, _cryptoProvider(nullptr),
      _lastTlsCallbackStatus(Crypto::TlsAsyncStatus::Idle) {
  _tlsTransport.bind(currentSocket());
  _tlsSession.bindTransport(_tlsTransport);
}

SecureClient::SecureClient(TransportProvider &provider)
    : EthernetClient(provider), _lastError(SecureClientNoError),
      _trustAnchors(nullptr), _trustAnchorLength(0),
      _clientCertificate(nullptr), _clientCertificateLength(0),
      _clientPrivateKey(nullptr), _clientPrivateKeyLength(0),
      _alpnProtocols(nullptr), _trustedUnixTime(0),
      _tlsOperationPollLimit(Crypto::DefaultTlsOperationPollLimit),
      _tlsSecurityLevel(SecureClientTlsSecurityLevel::High),
      _tlsSessionReuseEnabled(false), _tlsHandshakePending(false),
      _trustedTimeConfigured(false), _hostname{}, _cryptoProvider(nullptr),
      _lastTlsCallbackStatus(Crypto::TlsAsyncStatus::Idle) {}

SecureClient::SecureClient(SecureClient &&other)
    : EthernetClient(static_cast<EthernetClient &&>(other)),
      _lastError(other._lastError), _trustAnchors(other._trustAnchors),
      _trustAnchorLength(other._trustAnchorLength),
      _clientCertificate(other._clientCertificate),
      _clientCertificateLength(other._clientCertificateLength),
      _clientPrivateKey(other._clientPrivateKey),
      _clientPrivateKeyLength(other._clientPrivateKeyLength),
      _alpnProtocols(other._alpnProtocols),
      _trustedUnixTime(other._trustedUnixTime),
      _tlsOperationPollLimit(other._tlsOperationPollLimit),
      _tlsSecurityLevel(other._tlsSecurityLevel),
      _tlsSessionReuseEnabled(other._tlsSessionReuseEnabled),
      _tlsHandshakePending(other._tlsHandshakePending),
      _trustedTimeConfigured(other._trustedTimeConfigured), _hostname{},
      _cryptoProvider(other._cryptoProvider),
      _lastTlsCallbackStatus(other._lastTlsCallbackStatus) {
  strncpy(_hostname, other._hostname, sizeof(_hostname) - 1);
  _hostname[sizeof(_hostname) - 1] = '\0';
  memcpy(_tlsRxBuffer, other._tlsRxBuffer, sizeof(_tlsRxBuffer));
  _tlsRxLength = other._tlsRxLength;
  _tlsRxIndex = other._tlsRxIndex;
  _tlsRxPending = other._tlsRxPending;
  memcpy(_tlsTxBuffer, other._tlsTxBuffer, sizeof(_tlsTxBuffer));
  _tlsTxLength = other._tlsTxLength;
  _tlsTxPending = other._tlsTxPending;
  _tlsSession.configurePolicy(other.tlsPolicy());
  prepareTlsSession();
  other.clearTlsState();
  other._lastError = SecureClientNoError;
}

SecureClient &SecureClient::operator=(SecureClient &&other) {
  if (this == &other)
    return *this;

  EthernetClient::operator=(static_cast<EthernetClient &&>(other));
  _lastError = other._lastError;
  _trustAnchors = other._trustAnchors;
  _trustAnchorLength = other._trustAnchorLength;
  _clientCertificate = other._clientCertificate;
  _clientCertificateLength = other._clientCertificateLength;
  _clientPrivateKey = other._clientPrivateKey;
  _clientPrivateKeyLength = other._clientPrivateKeyLength;
  _alpnProtocols = other._alpnProtocols;
  _trustedUnixTime = other._trustedUnixTime;
  _tlsOperationPollLimit = other._tlsOperationPollLimit;
  _tlsSecurityLevel = other._tlsSecurityLevel;
  _tlsSessionReuseEnabled = other._tlsSessionReuseEnabled;
  _tlsHandshakePending = other._tlsHandshakePending;
  _trustedTimeConfigured = other._trustedTimeConfigured;
  memset(_hostname, 0, sizeof(_hostname));
  strncpy(_hostname, other._hostname, sizeof(_hostname) - 1);
  _hostname[sizeof(_hostname) - 1] = '\0';
  _cryptoProvider = other._cryptoProvider;
  _lastTlsCallbackStatus = other._lastTlsCallbackStatus;
  memcpy(_tlsRxBuffer, other._tlsRxBuffer, sizeof(_tlsRxBuffer));
  _tlsRxLength = other._tlsRxLength;
  _tlsRxIndex = other._tlsRxIndex;
  _tlsRxPending = other._tlsRxPending;
  memcpy(_tlsTxBuffer, other._tlsTxBuffer, sizeof(_tlsTxBuffer));
  _tlsTxLength = other._tlsTxLength;
  _tlsTxPending = other._tlsTxPending;
  _tlsSession.configurePolicy(other.tlsPolicy());
  prepareTlsSession();
  other.clearTlsState();
  other._lastError = SecureClientNoError;
  return *this;
}

int SecureClient::connect(IPAddress ip, uint16_t port) {
  if (!tlsAvailable()) {
    _lastError = SecureClientTlsUnavailable;
    return 0;
  }
  applyProviderTimeForTls();
  if (!tlsConfigurationReady()) {
    _lastError = SecureClientTlsNotConfigured;
    return 0;
  }

  const int result = EthernetClient::connect(ip, port);
  if (result == 0) {
    _lastError = SecureClientConnectFailed;
    return 0;
  }

  _tlsHandshakePending = true;
  if (EthernetClient::connected()) {
    _tlsHandshakePending = false;
    if (!startTlsHandshake()) {
      stop();
      _lastError = SecureClientTlsHandshakeStartFailed;
      return 0;
    }
  }

  _lastError = SecureClientNoError;
  return result;
}

int SecureClient::connect(const char *host, uint16_t port) {
  if (!tlsAvailable()) {
    _lastError = SecureClientTlsUnavailable;
    return 0;
  }
  applyProviderTimeForTls();
  if (!setHostname(host)) {
    _lastError = SecureClientTlsNotConfigured;
    return 0;
  }
  if (!tlsConfigurationReady()) {
    _lastError = SecureClientTlsNotConfigured;
    return 0;
  }

  const int result = EthernetClient::connect(host, port);
  if (result == 0) {
    _lastError = SecureClientConnectFailed;
    return 0;
  }

  _tlsHandshakePending = true;
  if (EthernetClient::connected()) {
    _tlsHandshakePending = false;
    if (!startTlsHandshake()) {
      stop();
      _lastError = SecureClientTlsHandshakeStartFailed;
      return 0;
    }
  }

  _lastError = SecureClientNoError;
  return result;
}

bool SecureClient::setTrustAnchors(const uint8_t *data, size_t length) {
  if (data == nullptr || length == 0)
    return false;

  _trustAnchors = data;
  _trustAnchorLength = length;
  if (!_tlsSession.configureTrustAnchors(data, length)) {
    _trustAnchors = nullptr;
    _trustAnchorLength = 0;
    return false;
  }

  return true;
}

bool SecureClient::setHostname(const char *hostname) {
  if (hostname == nullptr || hostname[0] == '\0')
    return false;

  memset(_hostname, 0, sizeof(_hostname));
  strncpy(_hostname, hostname, sizeof(_hostname) - 1);
  _hostname[sizeof(_hostname) - 1] = '\0';
  return _tlsSession.setHostname(_hostname);
}

bool SecureClient::setClientIdentity(const uint8_t *certificate,
                                     size_t certificateLength,
                                     const uint8_t *privateKey,
                                     size_t privateKeyLength) {
  if (certificate == nullptr || certificateLength == 0 ||
      privateKey == nullptr || privateKeyLength == 0)
    return false;

  _clientCertificate = certificate;
  _clientCertificateLength = certificateLength;
  _clientPrivateKey = privateKey;
  _clientPrivateKeyLength = privateKeyLength;
  if (!_tlsSession.configureClientIdentity(certificate, certificateLength,
                                           privateKey, privateKeyLength)) {
    _clientCertificate = nullptr;
    _clientCertificateLength = 0;
    _clientPrivateKey = nullptr;
    _clientPrivateKeyLength = 0;
    return false;
  }

  return true;
}

bool SecureClient::setAlpnProtocols(const char *const *protocols) {
  if (!_tlsSession.configureAlpnProtocols(protocols))
    return false;

  _alpnProtocols = protocols;
  return true;
}

const char *SecureClient::negotiatedAlpnProtocol() const {
  return _tlsSession.negotiatedAlpnProtocol();
}

bool SecureClient::peerCertificateSha256(
    uint8_t digest[Crypto::TlsSha256DigestLength]) const {
  return _tlsSession.peerCertificateSha256(digest);
}

bool SecureClient::peerSubjectPublicKeyInfoSha256(
    uint8_t digest[Crypto::TlsSha256DigestLength]) const {
  return _tlsSession.peerSubjectPublicKeyInfoSha256(digest);
}

bool SecureClient::setTrustedTime(uint64_t unixTime) {
  if (!_tlsSession.configureTrustedTime(unixTime))
    return false;

  _trustedUnixTime = unixTime;
  _trustedTimeConfigured = true;
  return true;
}

void SecureClient::clearTrustedTime() {
  _tlsSession.clearTrustedTime();
  if (_tlsSession.trustedTimeConfigured())
    return;

  _trustedUnixTime = 0;
  _trustedTimeConfigured = false;
}

bool SecureClient::trustedTimeConfigured() const {
  return _trustedTimeConfigured;
}

uint64_t SecureClient::trustedUnixTime() const { return _trustedUnixTime; }

bool SecureClient::setCryptoProvider(Crypto::TlsCryptoProvider &provider) {
  _cryptoProvider = &provider;
  return _tlsSession.bindCryptoProvider(provider);
}

bool SecureClient::setTlsPolicy(const Crypto::TlsClientPolicy &policy) {
  if (!_tlsSession.configurePolicy(policy))
    return false;

  _tlsSecurityLevel =
      policy.verification == Crypto::TlsVerificationPolicy::InsecureNoVerify
          ? SecureClientTlsSecurityLevel::Low
          : SecureClientTlsSecurityLevel::High;
  return true;
}

const Crypto::TlsClientPolicy &SecureClient::tlsPolicy() const {
  return _tlsSession.policy();
}

bool SecureClient::setTlsSecurityLevel(SecureClientTlsSecurityLevel level) {
  Crypto::TlsClientPolicy policy = tlsPolicy();
  policy.verification = level == SecureClientTlsSecurityLevel::Low
                            ? Crypto::TlsVerificationPolicy::InsecureNoVerify
                            : Crypto::TlsVerificationPolicy::Required;
  if (!_tlsSession.configurePolicy(policy))
    return false;

  _tlsSecurityLevel = level;
  return true;
}

SecureClientTlsSecurityLevel SecureClient::tlsSecurityLevel() const {
  return _tlsSecurityLevel;
}

bool SecureClient::setTlsOperationPollLimit(uint16_t pollLimit) {
  if (!_tlsSession.configureOperationPollLimit(pollLimit))
    return false;

  _tlsOperationPollLimit = pollLimit;
  return true;
}

uint16_t SecureClient::tlsOperationPollLimit() const {
  return _tlsOperationPollLimit;
}

bool SecureClient::enableTlsSessionReuse(bool enabled) {
  if (!_tlsSession.enableSessionReuse(enabled))
    return false;

  _tlsSessionReuseEnabled = enabled;
  return true;
}

bool SecureClient::tlsSessionReuseEnabled() const {
  return _tlsSessionReuseEnabled;
}

bool SecureClient::tlsSessionCached() const {
  return _tlsSession.sessionCached();
}

bool SecureClient::clearTlsSessionCache() {
  return _tlsSession.clearSessionCache();
}

Crypto::TlsAsyncStatus SecureClient::pollTls() { return advanceTlsOperation(); }

Crypto::TlsAsyncStatus SecureClient::tlsStatus() const {
  return _tlsSession.status();
}

int SecureClient::tlsLastError() const { return _tlsSession.lastError(); }

int SecureClient::tlsLastMbedTlsResult() const {
  return _tlsSession.lastMbedTlsResult();
}

int SecureClient::tlsHandshakeState() const {
  return _tlsSession.handshakeState();
}

uint32_t SecureClient::tlsBioSendCalls() const {
  return _tlsSession.bioSendCalls();
}

uint32_t SecureClient::tlsBioRecvCalls() const {
  return _tlsSession.bioRecvCalls();
}

uint32_t SecureClient::tlsBioRecvWantReadCount() const {
  return _tlsSession.bioRecvWantReadCount();
}

size_t SecureClient::tlsBioBytesSent() const {
  return _tlsSession.bioBytesSent();
}

size_t SecureClient::tlsBioBytesReceived() const {
  return _tlsSession.bioBytesReceived();
}

size_t SecureClient::tlsBioLastSendLength() const {
  return _tlsSession.bioLastSendLength();
}

size_t SecureClient::tlsBioLastSendAccepted() const {
  return _tlsSession.bioLastSendAccepted();
}

size_t SecureClient::tlsBioLastRecvLength() const {
  return _tlsSession.bioLastRecvLength();
}

int SecureClient::tlsBioLastRecvAvailable() const {
  return _tlsSession.bioLastRecvAvailable();
}

Crypto::TlsOperation SecureClient::tlsOperation() const {
  return _tlsSession.operation();
}

bool SecureClient::tlsHandshakePending() const { return _tlsHandshakePending; }

uint32_t SecureClient::tlsVerificationResult() const {
  return _tlsSession.verificationResult();
}

bool SecureClient::tlsHandshakeComplete() const {
  return _tlsSession.handshakeComplete();
}

bool SecureClient::tlsPeerCloseNotified() const {
  return _tlsSession.peerCloseNotified();
}

Crypto::TlsAsyncStatus SecureClient::closeNotifyAsync() {
  if (!tlsHandshakeComplete())
    return Crypto::TlsAsyncStatus::Error;

  const Crypto::TlsAsyncStatus started =
      _tlsSession.closeNotifyAsync(SecureClient::handleTlsCallback, this);
  if (started == Crypto::TlsAsyncStatus::Error)
    return started;

  return advanceTlsOperation();
}

size_t SecureClient::write(uint8_t value) { return write(&value, 1); }

size_t SecureClient::write(const uint8_t *buffer, size_t size) {
  if (!tlsHandshakeComplete() || buffer == nullptr || size == 0 ||
      _tlsTxPending)
    return 0;

  if (size > sizeof(_tlsTxBuffer))
    size = sizeof(_tlsTxBuffer);
  memcpy(_tlsTxBuffer, buffer, size);
  _tlsTxLength = size;
  _tlsTxPending = true;

  const Crypto::TlsAsyncStatus started = _tlsSession.writeAsync(
      _tlsTxBuffer, _tlsTxLength, SecureClient::handleTlsCallback, this);
  if (started == Crypto::TlsAsyncStatus::Error) {
    _tlsTxPending = false;
    _tlsTxLength = 0;
    return 0;
  }

  const Crypto::TlsAsyncStatus status = advanceTlsOperation();
  if (status == Crypto::TlsAsyncStatus::Error)
    return 0;

  return size;
}

int SecureClient::available() {
  if (!tlsHandshakeComplete())
    return 0;

  if (tlsRxAvailable() == 0)
    fillTlsRxBuffer();

  return static_cast<int>(tlsRxAvailable());
}

int SecureClient::read() {
  uint8_t value = 0;
  return read(&value, 1) == 1 ? value : -1;
}

int SecureClient::read(uint8_t *buffer, size_t size) {
  if (!tlsHandshakeComplete() || buffer == nullptr || size == 0)
    return 0;

  if (tlsRxAvailable() == 0 && !fillTlsRxBuffer())
    return 0;

  return static_cast<int>(consumeTlsRx(buffer, size));
}

int SecureClient::peek() {
  if (!tlsHandshakeComplete())
    return -1;

  if (tlsRxAvailable() == 0 && !fillTlsRxBuffer())
    return -1;

  return _tlsRxBuffer[_tlsRxIndex];
}

void SecureClient::flush() {
  if (currentSocket() != nullptr)
    currentSocket()->flush();
}

void SecureClient::stop() {
  _tlsHandshakePending = false;
  _tlsSession.abort();
  clearTlsStreamBuffers();
  _tlsTransport.clear();
  EthernetClient::stop();
}

uint8_t SecureClient::connected() {
  return tlsHandshakeComplete() && EthernetClient::connected() ? 1 : 0;
}

bool SecureClient::tlsAvailable() const {
  TransportProvider *provider = transportProvider();
  return provider != nullptr && provider->tlsAvailable();
}

int SecureClient::lastError() const { return _lastError; }

EthernetSocket *SecureClient::acquireProviderSocket() {
  TransportProvider *provider = transportProvider();
  if (provider == nullptr)
    return nullptr;

  return provider->acquireSecureClientSocket();
}

bool SecureClient::applyProviderTimeForTls() {
  if (_trustedTimeConfigured)
    return true;

  if (_tlsSecurityLevel == SecureClientTlsSecurityLevel::Low)
    return true;

  TransportProvider *provider = transportProvider();
  if (provider == nullptr)
    return false;

  NetworkTimeService *timeService = provider->networkTimeService();
  if (timeService == nullptr)
    return false;

  const NetworkTimeSnapshot snapshot = timeService->unixTime();
  const NetworkTimeLevel required =
      _tlsSecurityLevel == SecureClientTlsSecurityLevel::High
          ? NetworkTimeLevel::Trusted
          : NetworkTimeLevel::Provisional;
  if (snapshot.satisfies(required))
    return setTrustedTime(snapshot.unixTime);

  return false;
}

bool SecureClient::SocketTlsTransport::carrierUp() const {
  return _socket != nullptr && _socket->carrierUp();
}

uint8_t SecureClient::SocketTlsTransport::connected() {
  return _socket != nullptr ? _socket->connected() : 0;
}

size_t SecureClient::SocketTlsTransport::write(const uint8_t *buffer,
                                               size_t size) {
  if (_socket == nullptr || buffer == nullptr || size == 0 ||
      !_socket->connected())
    return 0;

  return _socket->write(buffer, size);
}

int SecureClient::SocketTlsTransport::available() {
  if (_socket == nullptr || !_socket->connected())
    return 0;

  return _socket->available();
}

int SecureClient::SocketTlsTransport::read(uint8_t *buffer, size_t size) {
  if (_socket == nullptr || buffer == nullptr || size == 0 ||
      !_socket->connected())
    return 0;

  return _socket->read(buffer, size);
}

void SecureClient::SocketTlsTransport::stop() {
  if (_socket != nullptr)
    _socket->stop();
}

bool SecureClient::tlsConfigurationReady() const {
  if (_tlsSecurityLevel == SecureClientTlsSecurityLevel::Low)
    return _cryptoProvider != nullptr;

  if (_trustAnchors == nullptr || _trustAnchorLength == 0 ||
      _hostname[0] == '\0' || _cryptoProvider == nullptr)
    return false;

  if (_tlsSecurityLevel == SecureClientTlsSecurityLevel::High)
    return _trustedTimeConfigured;

  return _trustedTimeConfigured;
}

bool SecureClient::prepareTlsSession() {
  _tlsTransport.bind(currentSocket());
  if (!_tlsSession.bindTransport(_tlsTransport))
    return false;
  if (!_tlsSession.configureOperationPollLimit(_tlsOperationPollLimit))
    return false;
  if (!_tlsSession.enableSessionReuse(_tlsSessionReuseEnabled))
    return false;
  if (_cryptoProvider != nullptr &&
      !_tlsSession.bindCryptoProvider(*_cryptoProvider))
    return false;
  if (_trustAnchors != nullptr && _trustAnchorLength != 0 &&
      !_tlsSession.configureTrustAnchors(_trustAnchors, _trustAnchorLength))
    return false;
  if (_clientCertificate != nullptr && _clientCertificateLength != 0 &&
      !_tlsSession.configureClientIdentity(
          _clientCertificate, _clientCertificateLength, _clientPrivateKey,
          _clientPrivateKeyLength))
    return false;
  if (!_tlsSession.configureAlpnProtocols(_alpnProtocols))
    return false;
  if (_trustedTimeConfigured &&
      !_tlsSession.configureTrustedTime(_trustedUnixTime))
    return false;
  if (_hostname[0] != '\0' && !_tlsSession.setHostname(_hostname))
    return false;

  return true;
}

bool SecureClient::startTlsHandshake() {
  if (!prepareTlsSession())
    return false;

  clearTlsStreamBuffers();
  const Crypto::TlsAsyncStatus status =
      _tlsSession.handshakeAsync(SecureClient::handleTlsCallback, this);
  return status != Crypto::TlsAsyncStatus::Error;
}

Crypto::TlsAsyncStatus SecureClient::advanceTlsOperation() {
  if (_tlsHandshakePending) {
    EthernetSocket *socket = currentSocket();
    if (socket == nullptr) {
      _tlsHandshakePending = false;
      _lastError = SecureClientConnectFailed;
      return Crypto::TlsAsyncStatus::Error;
    }

    const EthernetSocketState socketState = socket->state();
    if (socketState == EthernetSocketState::DnsPending ||
        socketState == EthernetSocketState::TcpConnecting)
      return Crypto::TlsAsyncStatus::Busy;

    if (socketState != EthernetSocketState::Connected) {
      _tlsHandshakePending = false;
      stop();
      _lastError = SecureClientConnectFailed;
      return Crypto::TlsAsyncStatus::Error;
    }

    _tlsHandshakePending = false;
    if (!startTlsHandshake()) {
      _lastError = SecureClientTlsHandshakeStartFailed;
      return Crypto::TlsAsyncStatus::Error;
    }
  }

  const Crypto::TlsOperation operation = _tlsSession.operation();
  const Crypto::TlsAsyncStatus status = _tlsSession.poll();
  if (_tlsRxPending && status == Crypto::TlsAsyncStatus::Complete) {
    _tlsRxLength = _tlsSession.bytesTransferred();
    _tlsRxIndex = 0;
    _tlsRxPending = false;
  } else if (_tlsRxPending && status == Crypto::TlsAsyncStatus::Error) {
    _tlsRxLength = 0;
    _tlsRxIndex = 0;
    _tlsRxPending = false;
  }

  if (_tlsTxPending && status == Crypto::TlsAsyncStatus::Complete) {
    memset(_tlsTxBuffer, 0, _tlsTxLength);
    _tlsTxLength = 0;
    _tlsTxPending = false;
  } else if (_tlsTxPending && status == Crypto::TlsAsyncStatus::Error) {
    memset(_tlsTxBuffer, 0, _tlsTxLength);
    _tlsTxLength = 0;
    _tlsTxPending = false;
  }

  if (operation == Crypto::TlsOperation::CloseNotify &&
      (status == Crypto::TlsAsyncStatus::Complete ||
       status == Crypto::TlsAsyncStatus::Error)) {
    clearTlsStreamBuffers();
    _tlsTransport.clear();
    EthernetClient::stop();
  } else if (operation == Crypto::TlsOperation::Handshake &&
             status == Crypto::TlsAsyncStatus::Error) {
    clearTlsStreamBuffers();
    _tlsTransport.clear();
    EthernetClient::stop();
  }

  return status;
}

bool SecureClient::fillTlsRxBuffer() {
  if (_tlsRxPending) {
    const Crypto::TlsAsyncStatus status = advanceTlsOperation();
    return status == Crypto::TlsAsyncStatus::Complete && tlsRxAvailable() != 0;
  }
  if (tlsRxAvailable() != 0 || _tlsTxPending)
    return tlsRxAvailable() != 0;

  _tlsRxLength = 0;
  _tlsRxIndex = 0;
  _tlsRxPending = true;
  const Crypto::TlsAsyncStatus started =
      _tlsSession.readAsync(_tlsRxBuffer, sizeof(_tlsRxBuffer),
                            SecureClient::handleTlsCallback, this);
  if (started == Crypto::TlsAsyncStatus::Error) {
    _tlsRxPending = false;
    return false;
  }

  const Crypto::TlsAsyncStatus status = advanceTlsOperation();
  return status == Crypto::TlsAsyncStatus::Complete && tlsRxAvailable() != 0;
}

size_t SecureClient::consumeTlsRx(uint8_t *buffer, size_t size) {
  const size_t availableBytes = tlsRxAvailable();
  if (buffer == nullptr || size == 0 || availableBytes == 0)
    return 0;

  const size_t count = size < availableBytes ? size : availableBytes;
  memcpy(buffer, _tlsRxBuffer + _tlsRxIndex, count);
  memset(_tlsRxBuffer + _tlsRxIndex, 0, count);
  _tlsRxIndex += count;
  if (_tlsRxIndex >= _tlsRxLength) {
    _tlsRxIndex = 0;
    _tlsRxLength = 0;
  }

  return count;
}

size_t SecureClient::tlsRxAvailable() const {
  return _tlsRxLength >= _tlsRxIndex ? _tlsRxLength - _tlsRxIndex : 0;
}

void SecureClient::clearTlsStreamBuffers() {
  memset(_tlsRxBuffer, 0, sizeof(_tlsRxBuffer));
  _tlsRxLength = 0;
  _tlsRxIndex = 0;
  _tlsRxPending = false;
  memset(_tlsTxBuffer, 0, sizeof(_tlsTxBuffer));
  _tlsTxLength = 0;
  _tlsTxPending = false;
}

void SecureClient::clearTlsState() {
  _tlsSession.abort();
  _tlsTransport.clear();
  _trustAnchors = nullptr;
  _trustAnchorLength = 0;
  _clientCertificate = nullptr;
  _clientCertificateLength = 0;
  _clientPrivateKey = nullptr;
  _clientPrivateKeyLength = 0;
  _alpnProtocols = nullptr;
  _trustedUnixTime = 0;
  _tlsSecurityLevel = SecureClientTlsSecurityLevel::High;
  _tlsSessionReuseEnabled = false;
  _tlsHandshakePending = false;
  _trustedTimeConfigured = false;
  memset(_hostname, 0, sizeof(_hostname));
  _cryptoProvider = nullptr;
  _lastTlsCallbackStatus = Crypto::TlsAsyncStatus::Idle;
  clearTlsStreamBuffers();
}

void SecureClient::handleTlsCallback(Crypto::TlsAsyncStatus status,
                                     void *context) {
  auto *client = static_cast<SecureClient *>(context);
  if (client != nullptr)
    client->_lastTlsCallbackStatus = status;
}
