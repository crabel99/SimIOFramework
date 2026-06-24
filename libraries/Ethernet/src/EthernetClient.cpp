#include "EthernetClient.h"

EthernetClient::EthernetClient() : _socket(nullptr) {}

EthernetClient::EthernetClient(EthernetSocket &socket) : _socket(&socket) {}

void EthernetClient::setSocket(EthernetSocket &socket) { _socket = &socket; }

void EthernetClient::clearSocket() { _socket = nullptr; }

int EthernetClient::connect(IPAddress ip, uint16_t port) {
  if (_socket == nullptr || !_socket->carrierUp())
    return 0;

  return _socket->connect(ip, port);
}

int EthernetClient::connect(const char *host, uint16_t port) {
  if (_socket == nullptr || host == nullptr || host[0] == '\0' ||
      !_socket->carrierUp())
    return 0;

  return _socket->connect(host, port);
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
}

uint8_t EthernetClient::connected() {
  if (_socket == nullptr)
    return 0;

  return _socket->connected();
}

EthernetClient::operator bool() { return _socket != nullptr; }
