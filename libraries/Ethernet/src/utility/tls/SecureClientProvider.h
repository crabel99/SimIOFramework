#pragma once

#include <utility/netif/EthernetSocketProvider.h>

class SecureClientProvider : public EthernetSocketProvider {
public:
  virtual bool tlsAvailable() const = 0;
};
