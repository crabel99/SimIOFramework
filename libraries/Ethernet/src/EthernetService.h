#pragma once

#include <EthernetClient.h>
#include <EthernetServer.h>
#include <EthernetUdp.h>
#include <SecureClient.h>
#include <utility/lwip/LwipPort.h>
#include <utility/netif/EthernetFrameDriver.h>
#include <utility/netif/EthernetPacket.h>
#include <utility/netif/EthernetServerProvider.h>
#include <utility/netif/EthernetSocketProvider.h>
#include <utility/netif/EthernetUdpProvider.h>
#include <utility/tls/SecureClientProvider.h>

class EthernetService {
public:
  EthernetService(EthernetFrameDriver &frameDriver,
                  EthernetPacketAllocator &packetAllocator);

  bool begin();
  void end();
  bool service();
  bool carrierUp() const;

  EthernetNetif &netif() { return _netif; }
  EthernetLwipPort &lwipPort() { return _lwipPort; }

  void setClientProvider(EthernetSocketProvider &provider);
  void clearClientProvider();
  void setServerProvider(EthernetServerProvider &provider);
  void clearServerProvider();
  void setUdpProvider(EthernetUdpProvider &provider);
  void clearUdpProvider();
  void setSecureClientProvider(SecureClientProvider &provider);
  void clearSecureClientProvider();

  EthernetClient client();
  EthernetServer server(uint16_t port);
  EthernetUDP udp();
  SecureClient secureClient();

private:
  EthernetPacketAllocator *_packetAllocator;
  EthernetNetif _netif;
  EthernetLwipPort _lwipPort;
  EthernetSocketProvider *_clientProvider;
  EthernetServerProvider *_serverProvider;
  EthernetUdpProvider *_udpProvider;
  SecureClientProvider *_secureClientProvider;
  bool _started;
};
