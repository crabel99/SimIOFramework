#pragma once

#include <utility/lwip/LwipPort.h>
#include <utility/lwip/LwipSocketBackend.h>
#include <utility/netif/FrameDriver.h>
#include <utility/netif/Netif.h>
#include <utility/network/NetworkConfig.h>

class NetworkService {
public:
  NetworkService(EthernetFrameDriver &frameDriver,
                 EthernetPacketAllocator &packetAllocator);

  bool begin();
  void end();
  bool service();
  bool carrierUp() const;
  void configureDhcp();
  void configureStatic(IPAddress localIp);
  void configureStatic(IPAddress localIp, IPAddress dnsServer);
  void configureStatic(IPAddress localIp, IPAddress dnsServer,
                       IPAddress gateway);
  void configureStatic(IPAddress localIp, IPAddress dnsServer,
                       IPAddress gateway, IPAddress subnet);
  const NetworkConfig &networkConfig() const { return _networkConfig; }
  bool networkConfigured() const;

  EthernetNetif &netif() { return _netif; }
  EthernetLwipPort &lwipPort() { return _lwipPort; }

private:
  EthernetPacketAllocator *_packetAllocator;
  EthernetNetif _netif;
  LwipSocketBackend _socketBackend;
  EthernetLwipPort _lwipPort;
  NetworkConfig _networkConfig;
  bool _started;
};
