#include "NetworkService.h"

NetworkService::NetworkService(EthernetFrameDriver &frameDriver,
                               EthernetPacketAllocator &packetAllocator)
    : _packetAllocator(&packetAllocator), _netif(frameDriver),
      _lwipPort(_netif), _socketBackend(), _networkConfig(), _started(false) {
  _lwipPort.setTcpBackend(_socketBackend);
  _lwipPort.setUdpBackend(_socketBackend);
}

bool NetworkService::begin() {
  if (_packetAllocator == nullptr)
    return false;

  _started = _lwipPort.begin(*_packetAllocator);
  return _started;
}

void NetworkService::end() {
  _lwipPort.end();
  _started = false;
}

bool NetworkService::service() {
  if (!_started)
    return false;

  return _lwipPort.service();
}

bool NetworkService::carrierUp() const { return _lwipPort.carrierUp(); }

void NetworkService::configureDhcp() {
  _networkConfig = NetworkConfig();
  _networkConfig.mode = NetworkAddressDhcp;
}

void NetworkService::configureStatic(IPAddress localIp) {
  configureStatic(localIp, IPAddress(), IPAddress(), IPAddress());
}

void NetworkService::configureStatic(IPAddress localIp, IPAddress dnsServer) {
  configureStatic(localIp, dnsServer, IPAddress(), IPAddress());
}

void NetworkService::configureStatic(IPAddress localIp, IPAddress dnsServer,
                                     IPAddress gateway) {
  configureStatic(localIp, dnsServer, gateway, IPAddress());
}

void NetworkService::configureStatic(IPAddress localIp, IPAddress dnsServer,
                                     IPAddress gateway, IPAddress subnet) {
  _networkConfig.mode = NetworkAddressStatic;
  _networkConfig.localIp = localIp;
  _networkConfig.dnsServer = dnsServer;
  _networkConfig.gateway = gateway;
  _networkConfig.subnet = subnet;
}

bool NetworkService::networkConfigured() const {
  return _networkConfig.mode != NetworkAddressUnconfigured;
}
