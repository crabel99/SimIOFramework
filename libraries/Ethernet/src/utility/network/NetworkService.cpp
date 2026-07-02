#include "NetworkService.h"

NetworkService::NetworkService(EthernetFrameDriver &frameDriver,
                               EthernetPacketAllocator &packetAllocator)
    : _packetAllocator(&packetAllocator), _netif(frameDriver), _socketBackend(),
      _lwipPort(_netif), _networkConfig(), _started(false) {
  _lwipPort.setTcpBackend(_socketBackend);
  _lwipPort.setUdpBackend(_socketBackend);
}

NetworkService::~NetworkService() { end(); }

bool NetworkService::begin() {
  if (_packetAllocator == nullptr)
    return false;

  _lwipPort.configureNetwork(_networkConfig);
  _started = _lwipPort.begin(*_packetAllocator);
  if (!_started)
    return false;
  if (!NetworkTime.begin(_lwipPort)) {
    _lwipPort.end();
    _started = false;
    return false;
  }
  if (!rtc::attachPeriodicInterrupt(rtc::PeriodicInterval::Per4,
                                    handleRtcTimeout, this)) {
    NetworkTime.detachProvider(_lwipPort);
    _lwipPort.end();
    _started = false;
    return false;
  }
  return true;
}

void NetworkService::end() {
  rtc::detachPeriodicInterrupt(rtc::PeriodicInterval::Per4);
  NetworkTime.detachProvider(_lwipPort);
  _lwipPort.end();
  _started = false;
}

bool NetworkService::service() {
  if (!_started)
    return false;

  const bool serviced = _lwipPort.service();
  NetworkTime.advance();
  return serviced;
}

void NetworkService::handleRtcTimeout(rtc::EventMask events, uint64_t,
                                      void *context) {
  if ((events & rtc::EventPeriodic4) == 0u || context == nullptr)
    return;

  static_cast<NetworkService *>(context)->_lwipPort.checkTimeouts();
}

bool NetworkService::carrierUp() const { return _lwipPort.carrierUp(); }

void NetworkService::configureDhcp() {
  _networkConfig = NetworkConfig();
  _networkConfig.mode = NetworkAddressDhcp;
  _lwipPort.configureNetwork(_networkConfig);
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
  _lwipPort.configureNetwork(_networkConfig);
}

bool NetworkService::networkConfigured() const {
  return _networkConfig.mode != NetworkAddressUnconfigured;
}

bool NetworkService::dhcpActive() const { return _lwipPort.dhcpActive(); }

bool NetworkService::dhcpAddressSupplied() const {
  return _lwipPort.dhcpAddressSupplied();
}

bool NetworkService::addressAssigned() const {
  return _lwipPort.addressAssigned();
}

IPAddress NetworkService::localIP() const { return _lwipPort.localIP(); }

IPAddress NetworkService::gatewayIP() const { return _lwipPort.gatewayIP(); }

IPAddress NetworkService::subnetMask() const { return _lwipPort.subnetMask(); }

IPAddress NetworkService::dnsServerIP() const {
  return _lwipPort.dnsServerIP();
}

void NetworkService::registerAsDefaultProvider() {
  TransportProvider::setDefaultProvider(_lwipPort);
}

void NetworkService::clearDefaultProvider() {
  if (TransportProvider::defaultProvider() == &_lwipPort)
    TransportProvider::clearDefaultProvider();
}
