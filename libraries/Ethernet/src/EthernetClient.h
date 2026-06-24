#pragma once

#include <Client.h>
#include <utility/netif/EthernetSocket.h>

class EthernetClient : public Client {
public:
  EthernetClient() : _socket(nullptr) {}
  explicit EthernetClient(EthernetSocket &socket) : _socket(&socket) {}

  void setSocket(EthernetSocket &socket) { _socket = &socket; }
  void clearSocket() { _socket = nullptr; }

  int connect(IPAddress ip, uint16_t port) override {
    if (_socket == nullptr || !_socket->carrierUp())
      return 0;

    return _socket->connect(ip, port);
  }

  int connect(const char *host, uint16_t port) override {
    if (_socket == nullptr || host == nullptr || host[0] == '\0' ||
        !_socket->carrierUp())
      return 0;

    return _socket->connect(host, port);
  }

  size_t write(uint8_t value) override {
    if (_socket == nullptr || !_socket->connected())
      return 0;

    return _socket->write(value);
  }

  size_t write(const uint8_t *buffer, size_t size) override {
    if (_socket == nullptr || buffer == nullptr || size == 0 ||
        !_socket->connected())
      return 0;

    return _socket->write(buffer, size);
  }

  int available() override {
    if (_socket == nullptr || !_socket->connected())
      return 0;

    return _socket->available();
  }

  int read() override {
    if (_socket == nullptr || !_socket->connected())
      return -1;

    return _socket->read();
  }

  int read(uint8_t *buffer, size_t size) override {
    if (_socket == nullptr || buffer == nullptr || size == 0 ||
        !_socket->connected())
      return 0;

    return _socket->read(buffer, size);
  }

  int peek() override {
    if (_socket == nullptr || !_socket->connected())
      return -1;

    return _socket->peek();
  }

  void flush() override {
    if (_socket != nullptr)
      _socket->flush();
  }

  void stop() override {
    if (_socket != nullptr)
      _socket->stop();
  }

  uint8_t connected() override {
    if (_socket == nullptr)
      return 0;

    return _socket->connected();
  }

  operator bool() override { return _socket != nullptr; }

  using Print::write;

private:
  EthernetSocket *_socket;
};
