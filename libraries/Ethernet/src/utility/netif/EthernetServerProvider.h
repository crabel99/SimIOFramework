#pragma once

#include <utility/netif/EthernetSocketProvider.h>

#include <stddef.h>
#include <stdint.h>

class EthernetServerProvider : public EthernetSocketProvider {
public:
  virtual bool beginServer(uint16_t port) = 0;
  virtual void stopServer(uint16_t port) = 0;
  virtual EthernetSocket *acceptClientSocket(uint16_t port) = 0;
  virtual size_t writeServer(uint16_t port, uint8_t value) = 0;
  virtual size_t writeServer(uint16_t port, const uint8_t *buffer,
                             size_t size) = 0;
};
