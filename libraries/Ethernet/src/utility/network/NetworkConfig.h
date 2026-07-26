#pragma once

#include <IPAddress.h>

enum NetworkAddressMode {
  NetworkAddressUnconfigured = 0,
  NetworkAddressDhcp,
  NetworkAddressStatic,
};

struct NetworkConfig {
  NetworkAddressMode mode = NetworkAddressUnconfigured;
  IPAddress localIp;
  IPAddress dnsServer;
  IPAddress gateway;
  IPAddress subnet;
};
