#include "EthernetService.h"

EthernetService::EthernetService(EthernetFrameDriver &frameDriver,
                                 EthernetPacketAllocator &packetAllocator)
    : _packetAllocator(&packetAllocator), _netif(frameDriver),
      _lwipPort(_netif), _clientProvider(nullptr), _serverProvider(nullptr),
      _udpProvider(nullptr), _secureClientProvider(nullptr), _started(false) {}

bool EthernetService::begin() {
  if (_packetAllocator == nullptr)
    return false;

  _started = _lwipPort.begin(*_packetAllocator);
  return _started;
}

void EthernetService::end() {
  _lwipPort.end();
  _started = false;
}

bool EthernetService::service() {
  if (!_started)
    return false;

  return _lwipPort.service();
}

bool EthernetService::carrierUp() const { return _lwipPort.carrierUp(); }

void EthernetService::setClientProvider(EthernetSocketProvider &provider) {
  _clientProvider = &provider;
}

void EthernetService::clearClientProvider() { _clientProvider = nullptr; }

void EthernetService::setServerProvider(EthernetServerProvider &provider) {
  _serverProvider = &provider;
}

void EthernetService::clearServerProvider() { _serverProvider = nullptr; }

void EthernetService::setUdpProvider(EthernetUdpProvider &provider) {
  _udpProvider = &provider;
}

void EthernetService::clearUdpProvider() { _udpProvider = nullptr; }

void EthernetService::setSecureClientProvider(SecureClientProvider &provider) {
  _secureClientProvider = &provider;
}

void EthernetService::clearSecureClientProvider() {
  _secureClientProvider = nullptr;
}

EthernetClient EthernetService::client() {
  if (_clientProvider == nullptr)
    return EthernetClient();

  return EthernetClient(*_clientProvider);
}

EthernetServer EthernetService::server(uint16_t port) {
  if (_serverProvider == nullptr)
    return EthernetServer(port);

  return EthernetServer(port, *_serverProvider);
}

EthernetUDP EthernetService::udp() {
  if (_udpProvider == nullptr)
    return EthernetUDP();

  return EthernetUDP(*_udpProvider);
}

SecureClient EthernetService::secureClient() {
  if (_secureClientProvider == nullptr)
    return SecureClient();

  return SecureClient(*_secureClientProvider);
}
