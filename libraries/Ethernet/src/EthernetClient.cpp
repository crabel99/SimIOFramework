#include "EthernetClient.h"

EthernetClient::EthernetClient()
    : _socket(nullptr), _provider(TransportProvider::defaultProvider()),
      _ownsSocket(false) {}

EthernetClient::EthernetClient(EthernetSocket &socket)
    : _socket(&socket), _provider(nullptr), _ownsSocket(false) {}

EthernetClient::EthernetClient(TransportProvider &provider)
    : _socket(nullptr), _provider(&provider), _ownsSocket(false) {}

EthernetClient::EthernetClient(TransportProvider &provider,
                               EthernetSocket &socket)
    : _socket(&socket), _provider(&provider), _ownsSocket(true) {}

EthernetClient::EthernetClient(EthernetClient &&other)
    : _socket(other._socket), _provider(other._provider),
      _ownsSocket(other._ownsSocket) {
  other._socket = nullptr;
  other._provider = nullptr;
  other._ownsSocket = false;
}

EthernetClient &EthernetClient::operator=(EthernetClient &&other) {
  if (this == &other)
    return *this;

  releaseOwnedSocket();
  _socket = other._socket;
  _provider = other._provider;
  _ownsSocket = other._ownsSocket;
  other._socket = nullptr;
  other._provider = nullptr;
  other._ownsSocket = false;
  return *this;
}

EthernetClient::~EthernetClient() { releaseOwnedSocket(); }

void EthernetClient::setSocket(EthernetSocket &socket) {
  releaseOwnedSocket();
  _socket = &socket;
  _provider = nullptr;
  _ownsSocket = false;
}

void EthernetClient::setTransportProvider(TransportProvider &provider) {
  releaseOwnedSocket();
  _socket = nullptr;
  _provider = &provider;
  _ownsSocket = false;
}

void EthernetClient::clearSocket() {
  releaseOwnedSocket();
  _socket = nullptr;
  _provider = nullptr;
  _ownsSocket = false;
}

int EthernetClient::connect(IPAddress ip, uint16_t port) {
  if (!ensureSocket())
    return 0;

  if (!_socket->carrierUp()) {
    if (_ownsSocket)
      releaseOwnedSocket();
    return 0;
  }

  const int result = _socket->connect(ip, port);
  if (result == 0 && _ownsSocket)
    releaseOwnedSocket();

  return result;
}

int EthernetClient::connect(const char *host, uint16_t port) {
  if (host == nullptr || host[0] == '\0')
    return 0;

  if (!ensureSocket())
    return 0;

  if (!_socket->carrierUp()) {
    if (_ownsSocket)
      releaseOwnedSocket();
    return 0;
  }

  const int result = _socket->connect(host, port);
  if (result == 0 && _ownsSocket)
    releaseOwnedSocket();

  return result;
}

size_t EthernetClient::write(uint8_t value) {
  if (_socket == nullptr || !_socket->connected())
    return 0;

  return _socket->write(value);
}

size_t EthernetClient::write(const uint8_t *buffer, size_t size) {
  if (_socket == nullptr || buffer == nullptr || size == 0 ||
      !_socket->connected())
    return 0;

  return _socket->write(buffer, size);
}

int EthernetClient::available() {
  if (_socket == nullptr || !_socket->connected())
    return 0;

  return _socket->available();
}

int EthernetClient::read() {
  if (_socket == nullptr || !_socket->connected())
    return -1;

  return _socket->read();
}

int EthernetClient::read(uint8_t *buffer, size_t size) {
  if (_socket == nullptr || buffer == nullptr || size == 0 ||
      !_socket->connected())
    return 0;

  return _socket->read(buffer, size);
}

int EthernetClient::peek() {
  if (_socket == nullptr || !_socket->connected())
    return -1;

  return _socket->peek();
}

void EthernetClient::flush() {
  if (_socket != nullptr)
    _socket->flush();
}

void EthernetClient::stop() {
  if (_socket != nullptr)
    _socket->stop();

  if (_ownsSocket)
    releaseOwnedSocket();
}

uint8_t EthernetClient::connected() {
  if (_socket == nullptr)
    return 0;

  return _socket->connected();
}

EthernetClient::operator bool() { return _socket != nullptr; }

bool EthernetClient::ensureSocket() {
  if (_socket != nullptr)
    return true;

  if (_provider == nullptr)
    return false;

  _socket = acquireProviderSocket();
  _ownsSocket = _socket != nullptr;
  return _socket != nullptr;
}

void EthernetClient::releaseOwnedSocket() {
  if (_ownsSocket && _provider != nullptr && _socket != nullptr)
    _provider->releaseSocket(_socket);

  if (_ownsSocket)
    _socket = nullptr;

  _ownsSocket = false;
}

EthernetSocket *EthernetClient::acquireProviderSocket() {
  if (_provider == nullptr)
    return nullptr;

  return _provider->acquireClientSocket();
}
