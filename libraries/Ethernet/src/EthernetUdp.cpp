#include "EthernetUdp.h"

EthernetUDP::EthernetUDP()
    : _provider(TransportProvider::defaultProvider()), _active(false) {}

EthernetUDP::EthernetUDP(TransportProvider &provider)
    : _provider(&provider), _active(false) {}

void EthernetUDP::setProvider(TransportProvider &provider) {
  stop();
  _provider = &provider;
}

void EthernetUDP::clearProvider() {
  stop();
  _provider = nullptr;
}

uint8_t EthernetUDP::begin(uint16_t port) {
  if (_provider == nullptr)
    return 0;

  const uint8_t result = _provider->beginUdp(port);
  _active = result != 0;
  return result;
}

uint8_t EthernetUDP::beginMulticast(IPAddress ip, uint16_t port) {
  if (_provider == nullptr)
    return 0;

  const uint8_t result = _provider->beginUdpMulticast(ip, port);
  _active = result != 0;
  return result;
}

void EthernetUDP::stop() {
  if (_provider != nullptr && _active)
    _provider->stopUdp();
  _active = false;
}

int EthernetUDP::beginPacket(IPAddress ip, uint16_t port) {
  if (_provider == nullptr)
    return 0;

  return _provider->beginUdpPacket(ip, port);
}

int EthernetUDP::beginPacket(const char *host, uint16_t port) {
  if (_provider == nullptr || host == nullptr || host[0] == '\0')
    return 0;

  return _provider->beginUdpPacket(host, port);
}

int EthernetUDP::endPacket() {
  if (_provider == nullptr)
    return 0;

  return _provider->endUdpPacket();
}

size_t EthernetUDP::write(uint8_t value) {
  if (_provider == nullptr)
    return 0;

  return _provider->writeUdp(value);
}

size_t EthernetUDP::write(const uint8_t *buffer, size_t size) {
  if (_provider == nullptr || buffer == nullptr || size == 0)
    return 0;

  return _provider->writeUdp(buffer, size);
}

int EthernetUDP::parsePacket() {
  if (_provider == nullptr)
    return 0;

  return _provider->parseUdpPacket();
}

int EthernetUDP::available() {
  if (_provider == nullptr)
    return 0;

  return _provider->availableUdp();
}

int EthernetUDP::read() {
  if (_provider == nullptr)
    return -1;

  return _provider->readUdp();
}

int EthernetUDP::read(unsigned char *buffer, size_t len) {
  if (_provider == nullptr || buffer == nullptr || len == 0)
    return 0;

  return _provider->readUdp(buffer, len);
}

int EthernetUDP::read(char *buffer, size_t len) {
  return read(reinterpret_cast<unsigned char *>(buffer), len);
}

int EthernetUDP::peek() {
  if (_provider == nullptr)
    return -1;

  return _provider->peekUdp();
}

void EthernetUDP::flush() {
  if (_provider != nullptr)
    _provider->flushUdp();
}

IPAddress EthernetUDP::remoteIP() {
  if (_provider == nullptr)
    return IPAddress();

  return _provider->remoteUdpIP();
}

uint16_t EthernetUDP::remotePort() {
  if (_provider == nullptr)
    return 0;

  return _provider->remoteUdpPort();
}
