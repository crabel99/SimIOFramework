#include "LwipTcpSocket.h"

void LwipTcpSocket::attach(LwipTcpSocketBackend &backend, void *handle) {
  _backend = &backend;
  _handle = handle;
}

void LwipTcpSocket::detach() {
  _backend = nullptr;
  _handle = nullptr;
}

bool LwipTcpSocket::carrierUp() const {
  return attached() && _backend->carrierUp(_handle);
}

EthernetSocketState LwipTcpSocket::state() {
  if (!attached())
    return EthernetSocketState::Closed;

  return _backend->state(_handle);
}

int LwipTcpSocket::connect(IPAddress ip, uint16_t port) {
  if (!attached())
    return 0;

  return _backend->connect(_handle, ip, port);
}

int LwipTcpSocket::connect(const char *host, uint16_t port) {
  if (!attached() || host == nullptr || host[0] == '\0')
    return 0;

  return _backend->connect(_handle, host, port);
}

size_t LwipTcpSocket::write(uint8_t value) {
  if (!attached())
    return 0;

  return _backend->write(_handle, value);
}

size_t LwipTcpSocket::write(const uint8_t *buffer, size_t size) {
  if (!attached() || buffer == nullptr || size == 0)
    return 0;

  return _backend->write(_handle, buffer, size);
}

int LwipTcpSocket::available() {
  if (!attached())
    return 0;

  return _backend->available(_handle);
}

int LwipTcpSocket::read() {
  if (!attached())
    return -1;

  return _backend->read(_handle);
}

int LwipTcpSocket::read(uint8_t *buffer, size_t size) {
  if (!attached() || buffer == nullptr || size == 0)
    return 0;

  return _backend->read(_handle, buffer, size);
}

int LwipTcpSocket::peek() {
  if (!attached())
    return -1;

  return _backend->peek(_handle);
}

void LwipTcpSocket::flush() {
  if (attached())
    _backend->flush(_handle);
}

void LwipTcpSocket::stop() {
  if (attached())
    _backend->stop(_handle);
}

uint8_t LwipTcpSocket::connected() {
  if (!attached())
    return 0;

  return _backend->connected(_handle);
}
