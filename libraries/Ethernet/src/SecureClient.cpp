#include "SecureClient.h"

#include <string.h>

SecureClient::SecureClient()
    : EthernetClient(), _lastError(SecureClientNoError), _trustAnchors(nullptr),
      _trustAnchorLength(0), _hostname{}, _cryptoProvider(nullptr),
      _lastTlsCallbackStatus(Crypto::TlsAsyncStatus::Idle) {}

SecureClient::SecureClient(EthernetSocket &socket)
    : EthernetClient(socket), _lastError(SecureClientNoError),
      _trustAnchors(nullptr), _trustAnchorLength(0), _hostname{},
      _cryptoProvider(nullptr),
      _lastTlsCallbackStatus(Crypto::TlsAsyncStatus::Idle) {
  _tlsTransport.bind(currentSocket());
  _tlsSession.bindTransport(_tlsTransport);
}

SecureClient::SecureClient(TransportProvider &provider)
    : EthernetClient(provider), _lastError(SecureClientNoError),
      _trustAnchors(nullptr), _trustAnchorLength(0), _hostname{},
      _cryptoProvider(nullptr),
      _lastTlsCallbackStatus(Crypto::TlsAsyncStatus::Idle) {}

SecureClient::SecureClient(SecureClient &&other)
    : EthernetClient(static_cast<EthernetClient &&>(other)),
      _lastError(other._lastError), _trustAnchors(other._trustAnchors),
      _trustAnchorLength(other._trustAnchorLength), _hostname{},
      _cryptoProvider(other._cryptoProvider),
      _lastTlsCallbackStatus(other._lastTlsCallbackStatus) {
  strncpy(_hostname, other._hostname, sizeof(_hostname) - 1);
  _hostname[sizeof(_hostname) - 1] = '\0';
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
  strncpy(_hostname, other._hostname, sizeof(_hostname) - 1);
  _hostname[sizeof(_hostname) - 1] = '\0';
  _cryptoProvider = other._cryptoProvider;
  _lastTlsCallbackStatus = other._lastTlsCallbackStatus;
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
  if (!tlsConfigurationReady()) {
    _lastError = SecureClientTlsNotConfigured;
    return 0;
  }

  const int result = EthernetClient::connect(ip, port);
  if (result == 0) {
    _lastError = SecureClientConnectFailed;
    return 0;
  }

  if (!startTlsHandshake()) {
    stop();
    _lastError = SecureClientTlsHandshakeStartFailed;
    return 0;
  }

  _lastError = SecureClientNoError;
  return result;
}

int SecureClient::connect(const char *host, uint16_t port) {
  if (!tlsAvailable()) {
    _lastError = SecureClientTlsUnavailable;
    return 0;
  }
  if (!setHostname(host) || !tlsConfigurationReady()) {
    _lastError = SecureClientTlsNotConfigured;
    return 0;
  }

  const int result = EthernetClient::connect(host, port);
  if (result == 0) {
    _lastError = SecureClientConnectFailed;
    return 0;
  }

  if (!startTlsHandshake()) {
    stop();
    _lastError = SecureClientTlsHandshakeStartFailed;
    return 0;
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

  strncpy(_hostname, hostname, sizeof(_hostname) - 1);
  _hostname[sizeof(_hostname) - 1] = '\0';
  return _tlsSession.setHostname(_hostname);
}

bool SecureClient::setCryptoProvider(Crypto::TlsCryptoProvider &provider) {
  _cryptoProvider = &provider;
  return _tlsSession.bindCryptoProvider(provider);
}

Crypto::TlsAsyncStatus SecureClient::pollTls() { return _tlsSession.poll(); }

Crypto::TlsAsyncStatus SecureClient::tlsStatus() const {
  return _tlsSession.status();
}

int SecureClient::tlsLastError() const { return _tlsSession.lastError(); }

uint32_t SecureClient::tlsVerificationResult() const {
  return _tlsSession.verificationResult();
}

bool SecureClient::tlsHandshakeComplete() const {
  return _tlsSession.handshakeComplete();
}

size_t SecureClient::write(uint8_t value) { return write(&value, 1); }

size_t SecureClient::write(const uint8_t *buffer, size_t size) {
  if (!tlsHandshakeComplete() || buffer == nullptr || size == 0)
    return 0;

  const Crypto::TlsAsyncStatus started =
      _tlsSession.writeAsync(buffer, size, SecureClient::handleTlsCallback, this);
  if (started == Crypto::TlsAsyncStatus::Error)
    return 0;

  const Crypto::TlsAsyncStatus status = _tlsSession.poll();
  return status == Crypto::TlsAsyncStatus::Complete
             ? _tlsSession.bytesTransferred()
             : 0;
}

int SecureClient::available() {
  if (!tlsHandshakeComplete())
    return 0;

  return 0;
}

int SecureClient::read() {
  uint8_t value = 0;
  return read(&value, 1) == 1 ? value : -1;
}

int SecureClient::read(uint8_t *buffer, size_t size) {
  if (!tlsHandshakeComplete() || buffer == nullptr || size == 0)
    return 0;

  const Crypto::TlsAsyncStatus started =
      _tlsSession.readAsync(buffer, size, SecureClient::handleTlsCallback, this);
  if (started == Crypto::TlsAsyncStatus::Error)
    return 0;

  const Crypto::TlsAsyncStatus status = _tlsSession.poll();
  return status == Crypto::TlsAsyncStatus::Complete
             ? static_cast<int>(_tlsSession.bytesTransferred())
             : 0;
}

int SecureClient::peek() { return -1; }

void SecureClient::flush() {
  if (currentSocket() != nullptr)
    currentSocket()->flush();
}

void SecureClient::stop() {
  _tlsSession.abort();
  _tlsTransport.clear();
  EthernetClient::stop();
}

uint8_t SecureClient::connected() {
  return EthernetClient::connected();
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
  return _trustAnchors != nullptr && _trustAnchorLength != 0 &&
         _hostname[0] != '\0' && _cryptoProvider != nullptr;
}

bool SecureClient::prepareTlsSession() {
  _tlsTransport.bind(currentSocket());
  if (!_tlsSession.bindTransport(_tlsTransport))
    return false;
  if (_cryptoProvider != nullptr &&
      !_tlsSession.bindCryptoProvider(*_cryptoProvider))
    return false;
  if (_trustAnchors != nullptr && _trustAnchorLength != 0 &&
      !_tlsSession.configureTrustAnchors(_trustAnchors, _trustAnchorLength))
    return false;
  if (_hostname[0] != '\0' && !_tlsSession.setHostname(_hostname))
    return false;

  return true;
}

bool SecureClient::startTlsHandshake() {
  if (!prepareTlsSession())
    return false;

  const Crypto::TlsAsyncStatus status = _tlsSession.handshakeAsync(
      SecureClient::handleTlsCallback, this);
  return status != Crypto::TlsAsyncStatus::Error;
}

void SecureClient::clearTlsState() {
  _tlsSession.abort();
  _tlsTransport.clear();
  _trustAnchors = nullptr;
  _trustAnchorLength = 0;
  _hostname[0] = '\0';
  _cryptoProvider = nullptr;
  _lastTlsCallbackStatus = Crypto::TlsAsyncStatus::Idle;
}

void SecureClient::handleTlsCallback(Crypto::TlsAsyncStatus status,
                                     void *context) {
  auto *client = static_cast<SecureClient *>(context);
  if (client != nullptr)
    client->_lastTlsCallbackStatus = status;
}
