#pragma once

#include <utility/netif/EthernetSocket.h>

class EthernetSocketProvider {
public:
  virtual ~EthernetSocketProvider() = default;

  virtual EthernetSocket *acquireClientSocket() = 0;
  virtual void releaseClientSocket(EthernetSocket *socket) = 0;
};
