#include "EthernetServer.h"

EthernetServer::EthernetServer(uint16_t port)
    : _port(port), _provider(nullptr), _listening(false) {}

EthernetServer::EthernetServer(uint16_t port,
                               EthernetServerProvider &provider)
    : _port(port), _provider(&provider), _listening(false) {}

EthernetServer::~EthernetServer() { stop(); }

void EthernetServer::setProvider(EthernetServerProvider &provider) {
  stop();
  _provider = &provider;
}

void EthernetServer::clearProvider() {
  stop();
  _provider = nullptr;
}

void EthernetServer::begin() {
  if (_provider == nullptr)
    return;

  _listening = _provider->beginServer(_port);
}

void EthernetServer::stop() {
  if (_provider != nullptr && _listening)
    _provider->stopServer(_port);

  _listening = false;
}

EthernetClient EthernetServer::available() { return accept(); }

EthernetClient EthernetServer::accept() {
  if (_provider == nullptr || !_listening)
    return EthernetClient();

  EthernetSocket *socket = _provider->acceptClientSocket(_port);
  if (socket == nullptr)
    return EthernetClient();

  return EthernetClient(*_provider, *socket);
}

size_t EthernetServer::write(uint8_t value) {
  if (_provider == nullptr || !_listening)
    return 0;

  return _provider->writeServer(_port, value);
}

size_t EthernetServer::write(const uint8_t *buffer, size_t size) {
  if (_provider == nullptr || !_listening || buffer == nullptr || size == 0)
    return 0;

  return _provider->writeServer(_port, buffer, size);
}
